/* Controlled resolver boundary tests. The installed offline HTTP test uses
 * real UDP DNS NXDOMAIN separately; this fixture controls callback ordering. */
#include <gio/gio.h>
#include <agent.h>

typedef struct { GResolver parent; GPtrArray *pending; } ControlledResolver;
typedef GResolverClass ControlledResolverClass;
G_DEFINE_TYPE (ControlledResolver, controlled_resolver, G_TYPE_RESOLVER)

static void lookup (GResolver *resolver, const gchar *hostname,
    GCancellable *cancel, GAsyncReadyCallback callback, gpointer data)
{
  GTask *task = g_task_new (resolver, cancel, callback, data);
  g_task_set_task_data (task, g_strdup (hostname), g_free);
  g_ptr_array_add (((ControlledResolver *) resolver)->pending, task);
}
static GList *finish (GResolver *resolver, GAsyncResult *result, GError **error)
{
  (void) resolver;
  return g_task_propagate_pointer (G_TASK (result), error);
}
static void finalize (GObject *object)
{
  g_ptr_array_unref (((ControlledResolver *) object)->pending);
  G_OBJECT_CLASS (controlled_resolver_parent_class)->finalize (object);
}
static void controlled_resolver_class_init (ControlledResolverClass *klass)
{
  klass->lookup_by_name_async = lookup;
  klass->lookup_by_name_finish = finish;
  G_OBJECT_CLASS (klass)->finalize = finalize;
}
static void controlled_resolver_init (ControlledResolver *resolver)
{
  resolver->pending = g_ptr_array_new_with_free_func (g_object_unref);
}
static void drain (void)
{
  while (g_main_context_pending (NULL)) g_main_context_iteration (NULL, FALSE);
}
static void free_addresses (gpointer addresses)
{
  g_list_free_full (addresses, g_object_unref);
}
static void resolve_one (ControlledResolver *resolver, gboolean success)
{
  GTask *task = g_ptr_array_steal_index (resolver->pending, 0);
  if (success) {
    GList *addresses = g_list_append (NULL, g_inet_address_new_from_string ("127.0.0.1"));
    g_task_return_pointer (task, addresses, free_addresses);
  } else {
    g_task_return_new_error (task, G_RESOLVER_ERROR, G_RESOLVER_ERROR_NOT_FOUND,
        "Controlled NXDOMAIN");
  }
  g_object_unref (task);
  drain ();
}
static void gathered (NiceAgent *agent, guint stream, gpointer data)
{
  (void) agent; (void) stream;
  ++*(guint *) data;
}
static void closed (GObject *agent, GAsyncResult *result, gpointer data)
{
  (void) agent; (void) result;
  ++*(guint *) data;
}
static NiceAgent *create (guint *count, gboolean stun)
{
  NiceAgent *agent = nice_agent_new (NULL, NICE_COMPATIBILITY_RFC5245);
  NiceAddress address;
  g_object_set (agent, "ice-tcp", FALSE, NULL);
  if (stun) g_object_set (agent, "stun-server", "stun.example.invalid", NULL);
  nice_address_init (&address);
  g_assert_true (nice_address_set_from_string (&address, "127.0.0.1"));
  g_assert_true (nice_agent_add_local_address (agent, &address));
  g_signal_connect (agent, "candidate-gathering-done", G_CALLBACK (gathered), count);
  return agent;
}
static guint gather_stream (NiceAgent *agent)
{
  guint stream = nice_agent_add_stream (agent, 1);
  g_assert_cmpuint (stream, >, 0);
  g_assert_true (nice_agent_gather_candidates (agent, stream));
  drain ();
  return stream;
}
static void close_agent (NiceAgent *agent)
{
  guint count = 0;
  nice_agent_close_async (agent, closed, &count);
  drain ();
  g_assert_cmpuint (count, ==, 1);
  g_object_unref (agent);
  drain ();
}
int main (void)
{
  GResolver *original = g_resolver_get_default ();
  ControlledResolver *resolver = g_object_new (controlled_resolver_get_type (), NULL);
  g_resolver_set_default (G_RESOLVER (resolver));
  guint count = 0;
  NiceAgent *agent = create (&count, TRUE);
  gather_stream (agent);gather_stream (agent);
  g_assert_cmpuint (resolver->pending->len, ==, 2);
  resolve_one (resolver, FALSE);
  g_assert_cmpuint (count, ==, 0); /* Second resolver still owns discovery. */
  resolve_one (resolver, FALSE);
  g_assert_cmpuint (count, ==, 2);
  close_agent (agent);

  count = 0;agent = create (&count, FALSE);
  guint stream = nice_agent_add_stream (agent, 1);
  g_assert_true (nice_agent_set_relay_info (agent, stream, 1, "turn.example.invalid",
      3478, "fixture", "fixture", NICE_RELAY_TYPE_TURN_UDP));
  g_assert_true (nice_agent_gather_candidates (agent, stream));drain ();
  g_assert_cmpuint (resolver->pending->len, ==, 1);
  resolve_one (resolver, FALSE);
  g_assert_cmpuint (count, ==, 1);
  close_agent (agent);

  count = 0;agent = create (&count, TRUE);stream = gather_stream (agent);
  nice_agent_remove_stream (agent, stream);
  resolve_one (resolver, TRUE); /* A late successful lookup cannot use a removed stream. */
  g_assert_cmpuint (count, ==, 0);
  close_agent (agent);

  count = 0;agent = create (&count, TRUE);gather_stream (agent);
  guint close_count = 0;
  nice_agent_close_async (agent, closed, &close_count);drain ();
  g_assert_cmpuint (close_count, ==, 0);
  resolve_one (resolver, FALSE);
  g_assert_cmpuint (close_count, ==, 1);g_assert_cmpuint (count, ==, 0);
  g_object_unref (agent);drain ();
  g_assert_cmpuint (resolver->pending->len, ==, 0);
  g_resolver_set_default (original);g_object_unref (original);g_object_unref (resolver);
  g_print ("STUN/TURN DNS completion, pending resolver ordering, removed stream and close cancellation passed\n");
  return 0;
}
