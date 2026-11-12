#include "configuration_store.hpp"
#include "endpoint_settings.hpp"
#include "tls_certificate.hpp"
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace traverse {
int ConfigurationIo::openRead(int directory,const char *name) const {
    return openat(directory,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
}
ssize_t ConfigurationIo::write(int fd,const void *data,size_t count) const {return ::write(fd,data,count);}
int ConfigurationIo::sync(int fd) const {return fsync(fd);}
int ConfigurationIo::replace(int directory,const char *temporary,const char *destination) const {
    return renameat(directory,temporary,directory,destination);
}
int ConfigurationIo::publishNew(int directory,const char *temporary,const char *destination) const {
    return linkat(directory,temporary,directory,destination,0);
}
namespace {
using json=nlohmann::json;
struct Fd {
    int value;
    explicit Fd(int fd):value(fd){}
    ~Fd(){if(value>=0)close(value);}
    Fd(const Fd&)=delete;
};
[[noreturn]] void error(ConfigurationProblem code,const char *message) {throw ConfigurationFailure(code,message);}
Fd directory(const std::filesystem::path &path) {
    Fd result(open(path.parent_path().c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
    struct stat metadata{};
    if(result.value<0 || fstat(result.value,&metadata) || metadata.st_uid!=geteuid() || (metadata.st_mode&0022))
        error(ConfigurationProblem::UnsafePath,"Settings require a directory owned and writable only by your account.");
    return Fd(std::exchange(result.value,-1));
}
ConfigurationSnapshot read(int directory,const char *name,const std::filesystem::path &parent,const ConfigurationIo &io) {
    Fd input(io.openRead(directory,name));
    struct stat before{},after{};
    if(input.value<0)error(ConfigurationProblem::Io,"Cannot read the saved settings.");
    if(fstat(input.value,&before) || !S_ISREG(before.st_mode) || before.st_uid!=geteuid() || (before.st_mode&0022))
        error(ConfigurationProblem::UnsafePath,"Settings must be a regular file owned and writable only by your account.");
    std::string bytes;
    std::array<char,4096> buffer{};
    while(true) {
        auto count=::read(input.value,buffer.data(),buffer.size());
        if(count>0)bytes.append(buffer.data(),size_t(count));
        else if(!count)break;
        else if(errno!=EINTR)error(ConfigurationProblem::Io,"Cannot read the saved settings.");
    }
    if(fstat(input.value,&after) || before.st_size!=after.st_size ||
       before.st_mtim.tv_sec!=after.st_mtim.tv_sec || before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec ||
       before.st_ctim.tv_sec!=after.st_ctim.tv_sec || before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)
        error(ConfigurationProblem::Changed,"Settings changed while being read. Reopen Settings.");
    try {
        auto value=json::parse(bytes);
        auto settings=EndpointSettings::parse(value,"",parent.string());
        if(settings.mode!=EndpointMode::Standalone)throw std::runtime_error("The host window requires versioned settings.");
        return {std::move(value),std::move(bytes),before.st_dev,before.st_ino};
    } catch(const json::parse_error &) {
        throw ConfigurationFailure(ConfigurationProblem::Validation,"The settings file is not valid JSON.");
    } catch(const std::exception &failure) {throw ConfigurationFailure(ConfigurationProblem::Validation,failure.what());}
}
void validate(const json &draft,const std::filesystem::path &parent) {
    try {
        auto settings=EndpointSettings::parse(draft,"",parent.string());
        if(settings.mode!=EndpointMode::Standalone)throw std::runtime_error("The host window requires versioned settings.");
        if(settings.certificates.mode==CertificateMode::Supplied) {
            TlsCertificateConfig options;
            options.certificate=settings.certificates.certificate;options.private_key=settings.certificates.private_key;
            options.expected_host=settings.domain;
            TlsCertificates certificates(options,[](SSL_CTX*){});
            if(!certificates.context() || !certificates.context()->valid_now())throw std::runtime_error("Certificate is not currently valid.");
        }
    } catch(const std::exception &failure) {throw ConfigurationFailure(ConfigurationProblem::Validation,failure.what());}
}
bool same(const ConfigurationSnapshot &left,const ConfigurationSnapshot &right) {
    return left.device==right.device && left.inode==right.inode && left.bytes==right.bytes;
}
bool named_directory(int fd,const std::filesystem::path &name) {
    struct stat held{},named{};
    return !fstat(fd,&held) && !lstat(name.c_str(),&named) && S_ISDIR(named.st_mode) &&
        held.st_dev==named.st_dev && held.st_ino==named.st_ino && named.st_uid==geteuid() && !(named.st_mode&0022);
}
struct Temporary {
    int directory;
    std::string name;
    struct stat identity{};
    Fd fd;
    explicit Temporary(int parent):directory(parent),fd(-1) {
        const char *hex="0123456789abcdef";
        while(true) {
            unsigned char bytes[16];
            if(RAND_bytes(bytes,sizeof(bytes))!=1)error(ConfigurationProblem::Io,"Cannot prepare settings storage.");
            name=".traverse-settings-";
            for(auto byte:bytes){name+=hex[byte>>4];name+=hex[byte&15];}
            fd.value=openat(directory,name.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
            if(fd.value>=0)break;
            if(errno!=EEXIST)error(ConfigurationProblem::Io,"Cannot prepare settings storage.");
        }
        if(fstat(fd.value,&identity))error(ConfigurationProblem::Io,"Cannot inspect settings storage.");
    }
    bool owned() const {
        struct stat current{};
        return !fstatat(directory,name.c_str(),&current,AT_SYMLINK_NOFOLLOW) &&
            S_ISREG(current.st_mode) && current.st_dev==identity.st_dev && current.st_ino==identity.st_ino;
    }
    ~Temporary(){if(owned())unlinkat(directory,name.c_str(),0);}
};
void sync(const ConfigurationIo &io,int fd) {
    while(io.sync(fd))if(errno!=EINTR)error(ConfigurationProblem::Io,"Cannot confirm settings storage.");
}
void prepare_parent(const std::filesystem::path &path,const ConfigurationIo &io) {
    std::filesystem::path current="/";
    for(const auto &part:path.relative_path()) {
        auto parent=current;current/=part;
        bool created=mkdir(current.c_str(),0700)==0;
        if(!created&&errno!=EEXIST)error(ConfigurationProblem::Io,"Cannot create the settings directory.");
        struct stat named{},target{};
        if(lstat(current.c_str(),&named)||stat(current.c_str(),&target)||!S_ISDIR(target.st_mode)||
           (named.st_uid!=0&&named.st_uid!=geteuid())||
           (target.st_uid!=0&&target.st_uid!=geteuid())||
           ((target.st_mode&0022)&&!(target.st_mode&S_ISVTX)))
            error(ConfigurationProblem::UnsafePath,"The settings directory path is unsafe.");
        // Trusted ancestor aliases such as /home -> /var/home are permitted;
        // the final application directory still uses directory() O_NOFOLLOW.
        if(created) {
            Fd ancestor(open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC));
            if(ancestor.value<0)error(ConfigurationProblem::Io,"Cannot confirm the settings directory.");
            sync(io,ancestor.value);
        }
    }
}
} // namespace
ConfigurationStore::ConfigurationStore(std::filesystem::path location,std::shared_ptr<ConfigurationIo> operations)
    :path(std::move(location)),io(std::move(operations)) {
    auto text=path.string();
    if(!path.is_absolute() || path.lexically_normal()!=path || path.filename().empty() ||
       text.find('\0')!=std::string::npos || !io)error(ConfigurationProblem::UnsafePath,"An absolute settings file is required.");
}
ConfigurationSnapshot ConfigurationStore::read() {
    std::lock_guard guard(mutex);
    auto parent=directory(path);
    auto value=traverse::read(parent.value,path.filename().c_str(),path.parent_path(),*io);
    if(!named_directory(parent.value,path.parent_path()))
        error(ConfigurationProblem::Changed,"The settings directory changed. Reopen Settings.");
    reconcile_required=false;
    return value;
}
ConfigurationSave ConfigurationStore::create(const json &draft) {
    std::lock_guard guard(mutex);
    if(reconcile_required)return {SaveOutcome::Uncertain,ConfigurationProblem::ReconcileRequired,"Reopen Traverse to confirm the saved settings.",std::nullopt};
    bool published=false;
    try {
        validate(draft,path.parent_path());
        prepare_parent(path.parent_path(),*io);
        auto parent=directory(path);
        auto lock_name="."+path.filename().string()+".lock";
        Fd lock(openat(parent.value,lock_name.c_str(),O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600));
        struct stat info{};
        if(lock.value<0||fstat(lock.value,&info)||!S_ISREG(info.st_mode)||info.st_uid!=geteuid()||(info.st_mode&0077))
            error(ConfigurationProblem::UnsafePath,"Cannot safely lock settings storage.");
        if(flock(lock.value,LOCK_EX|LOCK_NB))error(ConfigurationProblem::Busy,"Another settings save is in progress.");
        if(!fstatat(parent.value,path.filename().c_str(),&info,AT_SYMLINK_NOFOLLOW))
            error(ConfigurationProblem::Changed,"Settings already exist. Reopen Traverse.");
        if(errno!=ENOENT)error(ConfigurationProblem::Io,"Cannot inspect the settings destination.");
        Temporary temporary(parent.value);
        if(fchmod(temporary.fd.value,0600))error(ConfigurationProblem::Io,"Cannot protect saved settings.");
        auto body=draft.dump(2)+"\n";size_t offset=0;
        while(offset<body.size()) {
            auto count=io->write(temporary.fd.value,body.data()+offset,body.size()-offset);
            if(count>0)offset+=size_t(count);
            else if(count<0&&errno==EINTR)continue;
            else error(ConfigurationProblem::Io,"Cannot write the settings file.");
        }
        sync(*io,temporary.fd.value);
        if(!temporary.owned()||!named_directory(parent.value,path.parent_path()))
            error(ConfigurationProblem::Changed,"The settings directory changed before creation.");
        if(io->publishNew(parent.value,temporary.name.c_str(),path.filename().c_str())) {
            auto code=errno;
            struct stat actual{};
            published=!fstatat(parent.value,path.filename().c_str(),&actual,AT_SYMLINK_NOFOLLOW)&&
                actual.st_dev==temporary.identity.st_dev&&actual.st_ino==temporary.identity.st_ino;
            error(code==EEXIST?ConfigurationProblem::Changed:ConfigurationProblem::Io,
                code==EEXIST?"Settings appeared during setup. Reopen Traverse.":"Cannot confirm the settings creation.");
        }
        published=true;
        if(!temporary.owned()||unlinkat(parent.value,temporary.name.c_str(),0))
            error(ConfigurationProblem::Io,"Cannot confirm settings storage.");
        sync(*io,parent.value);
        auto saved=traverse::read(parent.value,path.filename().c_str(),path.parent_path(),*io);
        if(saved.bytes!=body||saved.device!=temporary.identity.st_dev||saved.inode!=temporary.identity.st_ino||
           !named_directory(parent.value,path.parent_path()))
            error(ConfigurationProblem::Changed,"Cannot confirm the created settings.");
        return {SaveOutcome::Saved,ConfigurationProblem::None,{},std::move(saved)};
    } catch(const ConfigurationFailure &failure) {
        reconcile_required=published;
        return {published?SaveOutcome::Uncertain:SaveOutcome::NotSaved,failure.problem,failure.what(),std::nullopt};
    } catch(const std::exception &) {
        reconcile_required=published;
        return {published?SaveOutcome::Uncertain:SaveOutcome::NotSaved,ConfigurationProblem::Io,"Cannot confirm the created settings.",std::nullopt};
    }
}
ConfigurationSave ConfigurationStore::save(const ConfigurationSnapshot &base,const json &draft) {
    std::lock_guard guard(mutex);
    if(reconcile_required)return {SaveOutcome::Uncertain,ConfigurationProblem::ReconcileRequired,"Reopen Settings to confirm what was saved.",std::nullopt};
    bool replace_attempted=false;
    try {
        validate(draft,path.parent_path());
        auto parent=directory(path);
        auto lock_name="."+path.filename().string()+".lock";
        Fd lock(openat(parent.value,lock_name.c_str(),O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600));
        struct stat metadata{};
        if(lock.value<0 || fstat(lock.value,&metadata) || !S_ISREG(metadata.st_mode) ||
           metadata.st_uid!=geteuid() || (metadata.st_mode&0077))
            error(ConfigurationProblem::UnsafePath,"Cannot safely lock settings storage.");
        if(flock(lock.value,LOCK_EX|LOCK_NB))error(ConfigurationProblem::Busy,"Another settings save is in progress.");
        auto current=traverse::read(parent.value,path.filename().c_str(),path.parent_path(),*io);
        if(!same(current,base))error(ConfigurationProblem::Changed,"Settings changed on disk. Reopen Settings.");
        struct stat destination{};
        if(fstatat(parent.value,path.filename().c_str(),&destination,AT_SYMLINK_NOFOLLOW) || !(destination.st_mode&S_IWUSR))
            error(ConfigurationProblem::UnsafePath,"The settings file is read-only.");
        Temporary temporary(parent.value);
        if(fchmod(temporary.fd.value,0600))error(ConfigurationProblem::Io,"Cannot protect saved settings.");
        auto body=draft.dump(2)+"\n";
        size_t offset=0;
        while(offset<body.size()) {
            auto count=io->write(temporary.fd.value,body.data()+offset,body.size()-offset);
            if(count>0)offset+=size_t(count);
            else if(count<0&&errno==EINTR)continue;
            else error(ConfigurationProblem::Io,"Cannot write the settings file.");
        }
        sync(*io,temporary.fd.value);
        if(!same(traverse::read(parent.value,path.filename().c_str(),path.parent_path(),*io),base) || !temporary.owned() ||
           !named_directory(parent.value,path.parent_path()))
            error(ConfigurationProblem::Changed,"Settings changed before save. Reopen Settings.");
        replace_attempted=true;
        if(io->replace(parent.value,temporary.name.c_str(),path.filename().c_str()))
            error(ConfigurationProblem::Io,"Cannot confirm the settings replacement.");
        sync(*io,parent.value);
        auto saved=traverse::read(parent.value,path.filename().c_str(),path.parent_path(),*io);
        if(saved.bytes!=body || saved.device!=temporary.identity.st_dev || saved.inode!=temporary.identity.st_ino ||
           !named_directory(parent.value,path.parent_path()))
            error(ConfigurationProblem::Changed,"Cannot confirm the saved settings.");
        return {SaveOutcome::Saved,ConfigurationProblem::None,{},std::move(saved)};
    } catch(const ConfigurationFailure &failure) {
        reconcile_required=replace_attempted;
        return {replace_attempted?SaveOutcome::Uncertain:SaveOutcome::NotSaved,failure.problem,failure.what(),std::nullopt};
    } catch(const std::exception &) {
        reconcile_required=replace_attempted;
        return {replace_attempted?SaveOutcome::Uncertain:SaveOutcome::NotSaved,ConfigurationProblem::Io,"Cannot confirm the saved settings.",std::nullopt};
    }
}
} // namespace traverse
