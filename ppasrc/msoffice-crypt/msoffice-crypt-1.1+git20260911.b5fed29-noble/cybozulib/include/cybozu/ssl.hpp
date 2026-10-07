#pragma once
/**
	@file
	@brief tiny wrapper of openssl class

	@author MITSUNARI Shigeo(@herumi)
*/
#include <cybozu/socket.hpp>
#include <cybozu/exception.hpp>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
//#include <openssl/crypto.h>
//#include <openssl/conf.h>
#ifdef _MSC_VER
	#include <cybozu/link_libeay32.hpp>
	#include <cybozu/link_ssleay32.hpp>
#endif

namespace cybozu {

namespace ssl {

struct Engine {
	Engine()
	{
		SSL_load_error_strings();
		SSL_library_init();
	}
	~Engine()
	{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && OPENSSL_VERSION_NUMBER < 0x10100000L
		ERR_remove_thread_state(0);
#elif OPENSSL_VERSION_NUMBER < 0x10000000L
		ERR_remove_state(0);
#endif
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ENGINE_cleanup();
		ERR_free_strings();
//		CONF_modules_unload(1); // openssl/conf.h
		/* this decreases one leak, but is this correct? */
		OPENSSL_free(SSL_COMP_get_compression_methods());
	}
	static Engine& getInstance()
	{
		static Engine engine;
		return engine;
	}
	void putError()
	{
		ERR_print_errors_fp(stderr);
	}
};

class Ctx {
	Engine& engine_;
	SSL_CTX *ctx_;
	Ctx(const Ctx&);
	void operator=(const Ctx&);
public:
	explicit Ctx()
		: engine_(Engine::getInstance())
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		, ctx_(SSL_CTX_new(TLS_client_method()))
#else
		, ctx_(SSL_CTX_new(TLSv1_client_method()))
#endif
	{
		if (ctx_ == 0) {
			engine_.putError();
			fprintf(stderr, "SSL_CTX_new:err");
			exit(1);
		}
#if 0
		if (SSL_CTX_set_cipher_list(ctx_, "ALL:eNULL") == 0) {
			engine_.putError();
			fprintf(stderr, "SSL_CTX_set_cipher_list:err");
			exit(1);
		}
#endif
	}
	~Ctx()
	{
		if (ctx_) SSL_CTX_free(ctx_);
	}
	SSL_CTX* get() const { return ctx_; }
};

namespace impl {
template<int dummy = 0>
struct InstanceIsHere { static Ctx ctx_; };

template<int dummy>
Ctx InstanceIsHere<dummy>::ctx_;

struct DummyCall {
	DummyCall() { InstanceIsHere<>::ctx_.get(); }
};

} // impl

class ClientSocket {
	cybozu::Socket soc_;
	SSL *ssl_;

	ClientSocket(const ClientSocket&);
	void operator=(const ClientSocket&);
public:
	ClientSocket()
		: ssl_(SSL_new(impl::InstanceIsHere<>::ctx_.get()))
	{
		if (ssl_ == 0) {
			throw cybozu::Exception("ssl:ClientSocket");
		}
	}
	void connect(const std::string& address, uint16_t port)
	{
		SocketAddr addr;
		addr.set(address, port);
		connect(addr);
	}
	void connect(const cybozu::SocketAddr& addr)
	{
		soc_.connect(addr);
		bool isOK;
#ifdef _WIN32
		if (soc_.sd_ > INT_MAX) {
			throw cybozu::Exception("ssl:ClientSocket:connect:large socket handle") << soc_.sd_;
		}
#endif
		isOK = SSL_set_fd(ssl_, static_cast<int>(soc_.sd_)) != 0;
		if (!isOK) goto ERR_EXIT;
		isOK = SSL_connect(ssl_) == 1;
		if (!isOK) goto ERR_EXIT;
		return;
	ERR_EXIT:
		Engine::getInstance().putError();
		throw cybozu::Exception("ssl:ClientSocket:connect");
	}
	size_t readSome(void *buf, size_t bufSize)
	{
		int size = (int)std::min((size_t)0x7fffffff, bufSize);
	RETRY:
		int ret = SSL_read(ssl_, buf, size);
		if (ret > 0) return ret;
		ret = SSL_get_error(ssl_, ret);
		if (ret == SSL_ERROR_ZERO_RETURN) return 0;
		if (ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE) goto RETRY;
		Engine::getInstance().putError();
		throw cybozu::Exception("ssl:ClientSocket:readSome") << ret;
	}
	void read(void *buf, size_t bufSize)
	{
		char *p = (char *)buf;
		while (bufSize > 0) {
			size_t readSize = readSome(p, bufSize);
			p += readSize;
			bufSize -= readSize;
		}
	}
	void write(const char *buf, size_t bufSize)
	{
		const char *p = (const char *)buf;
		while (bufSize > 0) {
			int size = (int)std::min((size_t)0x7fffffff, bufSize);
			int ret = SSL_write(ssl_, p, size);
			if (ret <= 0) {
				ret = SSL_get_error(ssl_, ret);
				if (ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE) continue;
				Engine::getInstance().putError();
				throw cybozu::Exception("ssl:ClientSocket:write") << ret;
			}
			p += ret;
			bufSize -= ret;
		}
	}
	void close(bool dontThrow = false)
	{
		bool isOK = true;
		if (soc_.isValid()) {
			isOK = SSL_shutdown(ssl_) == 1;
			if (!isOK) {
				Engine::getInstance().putError();
			}
			soc_.close(dontThrow);
		}
		if (!dontThrow && !isOK) throw cybozu::Exception("ssl:ClientSocket:close");
	}
	~ClientSocket()
	{
		if (ssl_) {
			close(cybozu::DontThrow);
			SSL_free(ssl_);
			ssl_ = 0;
		}
	}
};

} // cybozu::ssl

} // cybozu
