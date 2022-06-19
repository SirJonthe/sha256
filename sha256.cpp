#include "sha256.h"

static constexpr uint32_t INITIAL_HASH_VALUES[8] = {
	0x6a09e667U,
	0xbb67ae85U,
	0x3c6ef372U,
	0xa54ff53aU,
	0x510e527fU,
	0x9b05688cU,
	0x1f83d9abU,
	0x5be0cd19U
};

uint32_t sha256digest::rrot(uint32_t l, uint32_t r) const
{
	r = r & 31;
	const uint32_t lp = (l & ((1 << r) - 1)) << (32 - r);
	const uint32_t rp = l >> r;
	return lp | rp;
}

uint32_t sha256digest::zor(uint32_t a, uint32_t b, uint32_t c) const
{
	return a ^ b ^ c;
}

uint32_t sha256digest::sig(uint32_t x, uint32_t s1, uint32_t s2, uint32_t s3) const
{
	return zor(rrot(x, s1), rrot(x, s2), (x >> s3));
}

uint32_t sha256digest::SIG(uint32_t x, uint32_t s1, uint32_t s2, uint32_t s3) const
{
	return zor(rrot(x, s1), rrot(x, s2), rrot(x, s3));
}

uint32_t sha256digest::sig0(uint32_t x) const
{
	return sig(x, 7, 18, 3);
}

uint32_t sha256digest::sig1(uint32_t x) const
{
	return sig(x, 17, 19, 10);
}

uint32_t sha256digest::SIG0(uint32_t x) const
{
	return SIG(x, 2, 13, 22);
}

uint32_t sha256digest::SIG1(uint32_t x) const
{
	return SIG(x, 6, 11, 25);
}

uint32_t sha256digest::choice(uint32_t x, uint32_t y, uint32_t z) const
{
	return (x & y) ^ ((~x) & z);
}

uint32_t sha256digest::majority(uint32_t x, uint32_t y, uint32_t z) const
{
	return (x & y) ^ (x & z) ^ (y & z);
}

void sha256digest::blit(const char *src, uint8_t *dst) const
{
	memcpy(dst, src, BYTES_PER_BLOCK);
}

void sha256digest::blit(const char *src, uint8_t *dst, uint32_t num) const
{
	memcpy(dst, src, num);
	memset(dst + num, 0, BYTES_PER_BLOCK - num);
}

void sha256digest::create_schedule(const uint8_t *block, schedule_t &schedule) const
{
	// if (endian != LARGE_ENDIAN) {
	for (uint32_t i = 0, j = 0; i < 16; i++, j += 4) { // Split data in 32 bit blocks for the 16 first words
		schedule[i] = (uint32_t(block[j]) << 24) | (uint32_t(block[j + 1]) << 16) | (uint32_t(block[j + 2]) << 8) | uint32_t(block[j + 3]); // TODO: For big endian machines we do not need to reorganize the data.
	}
	// } else {
	// memcpy(schedule, block, BYTES_PER_BLOCK);
	// }
	for (uint32_t i = 16; i < WORDS_PER_SCHEDULE; ++i) {
		schedule[i] = sig1(schedule[i-2]) + schedule[i-7] + sig0(schedule[i-15]) + schedule[i-16];
	}
}

void sha256digest::process_block(const uint8_t *block, uint32_t *X) const
{
	static constexpr schedule_t K = {
		0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
		0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
		0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
		0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
		0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
		0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
		0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
		0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
		0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
		0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
		0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
		0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
		0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
		0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
		0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
		0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
	};

	schedule_t S;
	create_schedule(block, S);

	enum { A, B, C, D, E, F, G, H, REG_COUNT };

	uint32_t V[REG_COUNT];
	for (uint32_t i = 0; i < REG_COUNT; ++i) {
		V[i] = X[i];
	}

	for (uint32_t i = 0; i < WORDS_PER_SCHEDULE; ++i) {
		const uint32_t T1 = SIG1(V[E]) + choice(V[E], V[F], V[G]) + V[H] + K[i] + S[i];
		const uint32_t T2 = SIG0(V[A]) + majority(V[A], V[B], V[C]);

		for (uint32_t j = REG_COUNT - 1; j >= 1; --j) {
			V[j] = V[j-1];
		}
		V[E] += T1;
		V[A] = T1 + T2;
	}

	for (uint32_t i = 0; i < REG_COUNT; ++i) {
		X[i] += V[i];
	}
}

void sha256digest::convert_digest_endian(uint8_t *out) const
{
	for (uint32_t i = 0; i < sizeof(m_digest); i += sizeof(uint32_t)) {
		for (uint32_t j = 0; j < sizeof(uint32_t); ++j) {
			out[i + 3 - j] = m_digest.u8[i + j];
		}
	}
}

sha256digest::sha256digest( void )
{
	for (uint32_t i = 0; i < WORDS_PER_DIGEST; ++i) {
		m_digest.u32[i] = INITIAL_HASH_VALUES[i];
	}
}

sha256digest::sha256digest(const char *message) : sha256digest(message, uint64_t(strlen(message)))
{}

sha256digest::sha256digest(const char *message, uint64_t byte_count) : sha256digest()
{
	uint32_t  block_data[WORDS_PER_BLOCK]; // NOTE: Do this to ensure word alignment.
	uint8_t  *block = (uint8_t*)block_data;

	// Compute padding.
	const uint64_t ORIGINAL_MESSAGE_SIZE = byte_count;

	// Process every 512-bit block, except for partial or last one.
	/*if ((reinterpret_cast<const uintptr_t>(message) & (sizeof(uint32_t) * CHAR_BIT - 1)) != 0) { // The message is not aligned so we need to bit block transfer it to an aligned block before processing (mainly to ensure functioning on ARM processors).
		while (byte_count >= BYTES_PER_BLOCK) {
			blit(message, block);
			process_block(block, m_digest.u32);
			message += BYTES_PER_BLOCK;
			byte_count -= BYTES_PER_BLOCK;
		}
	} else { // The message is aligned so we can process it directly without aligning it manually.*/
		const uint8_t *M = (const uint8_t*)message;
		constexpr uint32_t BLOCK_WORDSIZE = BYTES_PER_BLOCK / sizeof(uint32_t);
		while (byte_count >= BYTES_PER_BLOCK) {
			process_block(M, m_digest.u32);
			message += BYTES_PER_BLOCK;
			byte_count -= BYTES_PER_BLOCK;
			M += BLOCK_WORDSIZE;
		}
	//}

	// The last block always needs to be processed manually since it always contains message size.
	blit(message, block, byte_count);

	// Store size (64 bits) of original message in bits at the end of the message
	uint32_t padding_size = BYTES_PER_BLOCK - (ORIGINAL_MESSAGE_SIZE % BYTES_PER_BLOCK);
	if (padding_size < sizeof(uint64_t) + sizeof(uint8_t)) { // Padding must at least fit a 64-bit number to denote message length in bits and one 8-bit number as a terminating 1-bit. If it does not, we add another block to process. Note that since we always work on bytes, not bits, the length of the terminating 1-bit is 8 bits, with a value of 0x80.
		padding_size += BYTES_PER_BLOCK;
	}

	// The message will always be padded in some way. Add a first '1' to the padding.
	block[byte_count] = PADDING_CONST;
	byte_count += padding_size;

	if (byte_count > BYTES_PER_BLOCK) { // Two blocks left to process.
		process_block(block, m_digest.u32);
		byte_count -= BYTES_PER_BLOCK;
		memset(block, 0, BYTES_PER_BLOCK - sizeof(uint64_t));
	}

	// One block left to process.
	const uint64_t ORIGINAL_MESSAGE_BITSIZE = (ORIGINAL_MESSAGE_SIZE * CHAR_BIT);
	for (uint32_t i = 0; i < sizeof(uint64_t); ++i) {
		//block[BYTES_PER_BLOCK - sizeof(uint64_t) + i] = reinterpret_cast<const char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
		block[BYTES_PER_BLOCK - 1 - i] = reinterpret_cast<const char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
	}
	process_block(block, m_digest.u32);
	byte_count -= BYTES_PER_BLOCK;

	// Clear sensitive data.
	memset(block, 0, BYTES_PER_BLOCK);
}

bool sha256digest::operator==(const sha256digest &r) const
{
	for (uint32_t i = 0; i < sizeof(m_digest) / sizeof(uint32_t); ++i) {
		if (m_digest.u32[i] != r.m_digest.u32[i]) {
			return false;
		}
	}
	return true;
}

bool sha256digest::operator!=(const sha256digest &r) const
{
	return !(*this == r);
}

// hex
// Returns the SHA256 digest as a human-readable hex string.
std::string sha256digest::hex( void ) const
{
	static constexpr char DIGITS[] = "0123456789abcdef";
	std::string out;
	out.resize(sizeof(m_digest) * 2);
	uint8_t digest[sizeof(m_digest)];
	convert_digest_endian(digest);
	for (uint32_t i = 0; i < sizeof(digest); ++i) {
		uint8_t b = digest[i];
		out[i * 2]       = DIGITS[b >> 4];
		out[(i * 2) + 1] = DIGITS[b & 15];
	}
	return out;
}

// bin
// Returns the SHA256 digest as a human-readable binary string.
std::string sha256digest::bin( void ) const
{
	std::string out;
	out.resize(sizeof(m_digest) * BITS_PER_BYTE);
	uint8_t digest[sizeof(m_digest)];
	convert_digest_endian(digest);
	for (uint32_t byte = 0; byte < sizeof(digest); ++byte) {
		for (uint32_t bit = 0; bit < BITS_PER_BYTE; ++bit) {
			out[byte * BITS_PER_BYTE + bit] = (digest[byte]  & (1 << (BITS_PER_BYTE - 1 - bit))) ? '1' : '0';
		}
	}
	return out;
}

// sha256
// Returns the SHA256 digest as a human-readable hex string.
std::string sha256(const char *message, uint64_t byte_count)
{
	return sha256digest(message, byte_count).hex();
}

// sha256
// Returns the SHA256 digest as a human-readable hex string.
std::string sha256(const char *message)
{
	return sha256digest(message).hex();
}
