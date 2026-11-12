#include "local_authority.hpp"
#include "endpoint_settings.hpp"
#include <arpa/inet.h>
#include <array>
#include <climits>
#include <ctime>
#include <iomanip>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <set>
#include <sstream>
#include <stdexcept>
namespace traverse {
namespace {
[[noreturn]] void invalid(){throw std::runtime_error("Local public certificate does not match the current authority.");}
std::int64_t integer(const nlohmann::json &value,const char *key) {
    if(!value.contains(key)||!value.at(key).is_number_integer()||value.at(key)<0||value.at(key)>253402300799LL)invalid();
    return value.at(key).get<std::int64_t>();
}
std::tm decoded(const ASN1_TIME *value) {std::tm result{};if(!ASN1_TIME_to_tm(value,&result))invalid();return result;}
std::int64_t timestamp(const ASN1_TIME *value) {auto result=decoded(value);return static_cast<std::int64_t>(timegm(&result));}
std::string hex(const unsigned char *bytes,size_t size) {
    std::ostringstream output;output<<std::hex<<std::setfill('0');for(size_t i=0;i<size;++i)output<<std::setw(2)<<static_cast<unsigned>(bytes[i]);return output.str();
}
std::multiset<std::string> subtrees(const STACK_OF(GENERAL_SUBTREE) *values) {
    std::multiset<std::string> result;
    for(int i=0;i<sk_GENERAL_SUBTREE_num(values);++i) {
        auto subtree=sk_GENERAL_SUBTREE_value(values,i);
        if(!subtree||!subtree->base||subtree->maximum||(subtree->minimum&&ASN1_INTEGER_get(subtree->minimum)!=0))invalid();
        auto base=subtree->base;
        if(base->type==GEN_DNS) {
            auto value=base->d.dNSName;auto length=ASN1_STRING_length(value);if(length<=0)invalid();
            result.insert("D:"+std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(value)),size_t(length)));
        } else if(base->type==GEN_IPADD) {
            auto value=base->d.iPAddress;auto length=ASN1_STRING_length(value);if(length!=8&&length!=32)invalid();
            result.insert("I:"+hex(ASN1_STRING_get0_data(value),size_t(length)));
        } else invalid();
    }
    return result;
}
void constraints(X509 *certificate,const std::string &domain) {
    int critical=-1;
    std::unique_ptr<NAME_CONSTRAINTS,decltype(&NAME_CONSTRAINTS_free)> value(
        static_cast<NAME_CONSTRAINTS*>(X509_get_ext_d2i(certificate,NID_name_constraints,&critical,nullptr)),NAME_CONSTRAINTS_free);
    if(!value||critical!=1)invalid();
    std::multiset<std::string> permitted,excluded;std::array<unsigned char,16> address{};int size=0;
    if(inet_pton(AF_INET,domain.c_str(),address.data())==1)size=4;
    else if(inet_pton(AF_INET6,domain.c_str(),address.data())==1)size=16;
    if(size) {
        permitted.insert("D:traverse-denied.invalid");excluded.insert("D:traverse-denied.invalid");
        std::string range=hex(address.data(),size_t(size));range.append(size_t(size)*2,'f');permitted.insert("I:"+range);
    } else {
        permitted.insert("D:"+domain);excluded.insert("D:."+domain);
        excluded.insert("I:"+std::string(16,'0'));excluded.insert("I:"+std::string(64,'0'));
    }
    if(subtrees(value->permittedSubtrees)!=permitted||subtrees(value->excludedSubtrees)!=excluded)invalid();
}
}
nlohmann::json checked_local_authority(const std::string &pem,const nlohmann::json &metadata,const std::string &hostname) {
    if(!metadata.is_object()||metadata.size()!=3||!metadata.contains("fingerprint")||!metadata.at("fingerprint").is_string())invalid();
    const auto from=integer(metadata,"validFrom"),until=integer(metadata,"validUntil");
    const auto now=std::time(nullptr);if(now<0||from>now||until<=now||until<=from||pem.size()>INT_MAX)invalid();
    const auto domain=EndpointSettings::normalize_host(hostname);
    std::unique_ptr<BIO,decltype(&BIO_free)> input(BIO_new_mem_buf(pem.data(),static_cast<int>(pem.size())),BIO_free);if(!input)invalid();
    std::unique_ptr<X509,decltype(&X509_free)> certificate(PEM_read_bio_X509(input.get(),nullptr,nullptr,nullptr),X509_free);
    char *rest=nullptr;auto remaining=BIO_get_mem_data(input.get(),&rest);
    if(!certificate||remaining<0||std::string(rest,size_t(remaining)).find_first_not_of(" \t\r\n")!=std::string::npos)invalid();
    // PEM_read_bio_X509 skips preceding blocks; require the first byte to be
    // the public certificate so a key or extra PEM block cannot be exported.
    if(pem.rfind("-----BEGIN CERTIFICATE-----",0)!=0||pem.find("PRIVATE KEY")!=std::string::npos)invalid();
    unsigned char digest[EVP_MAX_MD_SIZE];unsigned length=0;
    if(!X509_digest(certificate.get(),EVP_sha256(),digest,&length)||length!=32||metadata.at("fingerprint")!=hex(digest,length)||
       from!=timestamp(X509_get0_notBefore(certificate.get()))||until!=timestamp(X509_get0_notAfter(certificate.get())))invalid();
    auto anniversary=decoded(X509_get0_notBefore(certificate.get()));anniversary.tm_year+=10;
    if(until!=static_cast<std::int64_t>(timegm(&anniversary)))invalid();
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(X509_get_pubkey(certificate.get()),EVP_PKEY_free);
    char group[80]{};size_t group_length=0;
    if(!key||!EVP_PKEY_is_a(key.get(),"EC")||!EVP_PKEY_get_utf8_string_param(key.get(),OSSL_PKEY_PARAM_GROUP_NAME,group,sizeof(group),&group_length)||
       (std::string(group)!="prime256v1"&&std::string(group)!="P-256")||X509_get_signature_nid(certificate.get())!=NID_ecdsa_with_SHA256||
       X509_NAME_cmp(X509_get_subject_name(certificate.get()),X509_get_issuer_name(certificate.get()))||X509_verify(certificate.get(),key.get())!=1)invalid();
    int critical=-1;
    std::unique_ptr<BASIC_CONSTRAINTS,decltype(&BASIC_CONSTRAINTS_free)> basic(static_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(certificate.get(),NID_basic_constraints,&critical,nullptr)),BASIC_CONSTRAINTS_free);
    if(!basic||critical!=1||!basic->ca||!basic->pathlen||ASN1_INTEGER_get(basic->pathlen)!=0)invalid();
    std::unique_ptr<ASN1_BIT_STRING,decltype(&ASN1_BIT_STRING_free)> usage(static_cast<ASN1_BIT_STRING*>(X509_get_ext_d2i(certificate.get(),NID_key_usage,&critical,nullptr)),ASN1_BIT_STRING_free);
    if(!usage||critical!=1||ASN1_STRING_length(usage.get())!=1)invalid();
    for(int bit=0;bit<8;++bit)if(ASN1_BIT_STRING_get_bit(usage.get(),bit)!=int(bit==5||bit==6))invalid();
    std::unique_ptr<EXTENDED_KEY_USAGE,decltype(&EXTENDED_KEY_USAGE_free)> purposes(static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(certificate.get(),NID_ext_key_usage,&critical,nullptr)),EXTENDED_KEY_USAGE_free);
    if(!purposes||sk_ASN1_OBJECT_num(purposes.get())!=1||OBJ_obj2nid(sk_ASN1_OBJECT_value(purposes.get(),0))!=NID_server_auth)invalid();
    for(int nid:{NID_subject_alt_name,NID_info_access,NID_crl_distribution_points})if(X509_get_ext_by_NID(certificate.get(),nid,-1)>=0)invalid();
    for(int i=0;i<X509_get_ext_count(certificate.get());++i) {
        auto extension=X509_get_ext(certificate.get(),i);if(!X509_EXTENSION_get_critical(extension))continue;
        auto nid=OBJ_obj2nid(X509_EXTENSION_get_object(extension));
        if(nid!=NID_basic_constraints&&nid!=NID_key_usage&&nid!=NID_ext_key_usage&&nid!=NID_name_constraints)invalid();
    }
    constraints(certificate.get(),domain);
    auto result=metadata;result["version"]=1;result["domain"]=domain;result["pem"]=pem;return result;
}
}
