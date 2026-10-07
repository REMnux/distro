#include <stdio.h>
#include <stdlib.h>
#include <cybozu/minixml.hpp>
#include <cybozu/mmap.hpp>
#include <cybozu/test.hpp>
#include <cybozu/file.hpp>
#include <iostream>

typedef cybozu::minixml::InputStream<std::string::const_iterator> InputStream;

const std::string xmlData =
"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
"<encryption"
"  xmlns=\"http://schemas.microsoft.com/office/2006/encryption\""
"  xmlns:p=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\">"
"  <keyData"
"    saltSize=\"16\""
"    blockSize=\"16\""
"    keyBits=\"128\""
"    hashSize=\"20\""
"    cipherAlgorithm=\"AES\""
"    cipherChaining=\"ChainingModeCBC\""
"    hashAlgorithm=\"SHA1\""
"    saltValue=\"xJqq7pkATGsBfuXNEbhnKQ==\"/>"
"  <dataIntegrity"
"    encryptedHmacKey=\"rxCSo+nqBf18m0mctP82tZbBRRaC5h7DM1q7q/bKPrU=\""
"    encryptedHmacValue=\"yuBiZXxrtgU3WNRWahDolVZJ8PbwsI9w7Hksnu2UkvM=\"/>"
"  <keyEncryptors>"
"    <keyEncryptor"
"      uri=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\">"
"      <p:encryptedKey"
"        spinCount=\"100000\""
"        saltSize=\"16\""
"        blockSize=\"16\""
"        keyBits=\"128\""
"        hashSize=\"20\""
"        cipherAlgorithm=\"AES\""
"        cipherChaining=\"ChainingModeCBC\""
"        hashAlgorithm=\"SHA1\""
"        saltValue=\"9JlPmy3NXg6EvGOG1FI9LA==\""
"        encryptedVerifierHashInput=\"xpwBRhK5VWSrmM9kspOnwg==\""
"        encryptedVerifierHashValue=\"jpuVmPpsYgBZR1fvJ21E9BhRTtuIlbJsknEjEPz1wmI=\""
"        encryptedKeyValue=\"cnNcvlFXRSEykrLjpWgYlw==\"/>"
"    </keyEncryptor>"
"  </keyEncryptors>"
"</encryption>";

CYBOZU_TEST_AUTO(parse)
{
	try {
		InputStream is(xmlData.begin(), xmlData.end());
		cybozu::MiniXml xml;
		xml.parse(is);
		std::cout << xml << std::endl;
		const cybozu::minixml::Node *p = xml.get().getFirstTagByName("keyEncryptor");
		p->put();
	} catch (cybozu::Exception& e) {
		printf("e=%s\n", e.what());
	}
}

CYBOZU_TEST_AUTO(escape)
{
	std::string in = "input:&<>'\"abc";
	std::string out = "input:&amp;&lt;&gt;&apos;&quot;abc";
	CYBOZU_TEST_EQUAL(cybozu::minixml::escape(in), out);
	in.clear();
	for (int i = 0; i < 256; i++) {
		in.push_back(char(i));
	}
	out = cybozu::minixml::escape(in);
	std::string dec = cybozu::minixml::unescape(out);
	CYBOZU_TEST_EQUAL(in, dec);
}

CYBOZU_TEST_AUTO(example)
{
	std::string file = cybozu::GetExePath();
	{
		const std::string& key = "/cybozulib/";
		size_t pos = file.find(key);
		if (pos == std::string::npos) {
			CYBOZU_TEST_FAIL(file + " has no " + key);
			exit(1);
		}
		file.resize(pos + key.size());
		file += "test/base/data/a.xml";
		printf("file=[%s]\n", file.c_str());
	}

	cybozu::Mmap m(file);
	std::string data(m.get(), m.get() + m.size());
	try {
		InputStream is(data.begin(), data.end());
		cybozu::MiniXml xml;
		xml.parse(is);
		std::cout << xml << std::endl;
		const cybozu::minixml::Node *p = xml.get().getFirstTagByName("dish");
		if (p) p->put();
	} catch (cybozu::Exception& e) {
		printf("e=%s\n", e.what());
	}
}
