#pragma once
#include <filesystem>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <stdexcept>
#include <sys/types.h>

namespace traverse {
enum class ConfigurationProblem { None, Validation, UnsafePath, Changed, Busy, Io, ReconcileRequired };
class ConfigurationFailure : public std::runtime_error {
  public:
    ConfigurationProblem problem;
    ConfigurationFailure(ConfigurationProblem code,const std::string &message)
        :std::runtime_error(message),problem(code){}
};
struct ConfigurationSnapshot {
    nlohmann::json document;
    std::string bytes;
    dev_t device{};
    ino_t inode{};
};
enum class SaveOutcome { NotSaved, Saved, Uncertain };
struct ConfigurationSave {
    SaveOutcome outcome;
    ConfigurationProblem problem;
    std::string detail;
    std::optional<ConfigurationSnapshot> verified;
};
// Filesystem boundary for real-I/O failure tests, not a runtime feature switch.
struct ConfigurationIo {
    virtual ~ConfigurationIo()=default;
    virtual int openRead(int directory,const char *name) const;
    virtual ssize_t write(int fd,const void *data,size_t count) const;
    virtual int sync(int fd) const;
    virtual int replace(int directory,const char *temporary,const char *destination) const;
    virtual int publishNew(int directory,const char *temporary,const char *destination) const;
};
class ConfigurationStore {
    std::filesystem::path path;
    std::shared_ptr<ConfigurationIo> io;
    std::mutex mutex;
    bool reconcile_required=false;
  public:
    explicit ConfigurationStore(std::filesystem::path location,
        std::shared_ptr<ConfigurationIo> operations=std::make_shared<ConfigurationIo>());
    ConfigurationSnapshot read();
    ConfigurationSave create(const nlohmann::json &draft);
    ConfigurationSave save(const ConfigurationSnapshot &base,const nlohmann::json &draft);
};
} // namespace traverse
