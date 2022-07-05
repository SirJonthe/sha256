#include "sha256.h"

// Typedefs to ease reading.
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

// ENDIAN
// Constant to determine endianness of current machine.
constexpr union {
	struct Bytes {
		u8 a, b, c, d;
	} bytes;
	u32 word;
} ENDIAN = {
	{ 1, 2, 3, 4 }
};

// is_big
// Determines if the machine endian is big at run-time.
bool is_big( void )
{
	return ENDIAN.word == 0x01020304;
}

// is_lil
// Determines if the machine endian is little at run-time.
bool is_lil( void )
{
	return ENDIAN.word == 0x4030201;
}

static constexpr u32 INITIAL_HASH_VALUES[8] = {
	0x6a09e667U,
	0xbb67ae85U,
	0x3c6ef372U,
	0xa54ff53aU,
	0x510e527fU,
	0x9b05688cU,
	0x1f83d9abU,
	0x5be0cd19U
};

u32 sha256digest::rrot(u32 l, u32 r) const
{
	return (l >> r) | (l << (32 - r));
}

u32 sha256digest::zor(u32 a, u32 b, u32 c) const
{
	return a ^ b ^ c;
}

u32 sha256digest::sig(u32 x, u32 s1, u32 s2, u32 s3) const
{
	return zor(rrot(x, s1), rrot(x, s2), (x >> s3));
}

u32 sha256digest::SIG(u32 x, u32 s1, u32 s2, u32 s3) const
{
	return zor(rrot(x, s1), rrot(x, s2), rrot(x, s3));
}

u32 sha256digest::sig0(u32 x) const
{
	return sig(x, 7, 18, 3);
}

u32 sha256digest::sig1(u32 x) const
{
	return sig(x, 17, 19, 10);
}

u32 sha256digest::SIG0(u32 x) const
{
	return SIG(x, 2, 13, 22);
}

u32 sha256digest::SIG1(u32 x) const
{
	return SIG(x, 6, 11, 25);
}

u32 sha256digest::choice(u32 x, u32 y, u32 z) const
{
	return (x & y) ^ ((~x) & z);
}

u32 sha256digest::majority(u32 x, u32 y, u32 z) const
{
	return (x & y) ^ (x & z) ^ (y & z);
}

void sha256digest::blit(const char *src, u8 *dst) const
{
	memcpy(dst, src, BYTES_PER_BLOCK);
}

void sha256digest::blit(const char *src, u8 *dst, u32 num) const
{
	memcpy(dst, src, num);
	memset(dst + num, 0, BYTES_PER_BLOCK - num);
}

void sha256digest::create_schedule(const u8 *block, schedule_t &schedule) const
{
	if (is_lil()) { // NOTE: On little endian machines we need to convert input data to big endian.
		for (u32 i = 0, j = 0; i < 16; i++, j += 4) { // Split data in 32 bit blocks for the 16 first words
			schedule[i] = (u32(block[j]) << 24) | (u32(block[j + 1]) << 16) | (u32(block[j + 2]) << 8) | u32(block[j + 3]);
		}
	} else { // NOTE: We assume machines that are not little endian are big endian (this may not be true for some esoteric architectures).
		memcpy(schedule, block, BYTES_PER_BLOCK);
	}
	for (u32 i = 16; i < WORDS_PER_SCHEDULE; ++i) {
		schedule[i] = sig1(schedule[i-2]) + schedule[i-7] + sig0(schedule[i-15]) + schedule[i-16];
	}
}

void sha256digest::process_block(const u8 *block, u32 *X) const
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

	u32 V[REG_COUNT];
	for (u32 i = 0; i < REG_COUNT; ++i) {
		V[i] = X[i];
	}

	for (u32 i = 0; i < WORDS_PER_SCHEDULE; ++i) {
		const u32 T1 = SIG1(V[E]) + choice(V[E], V[F], V[G]) + V[H] + K[i] + S[i];
		const u32 T2 = SIG0(V[A]) + majority(V[A], V[B], V[C]);

		for (u32 j = REG_COUNT - 1; j >= 1; --j) {
			V[j] = V[j-1];
		}
		V[E] += T1;
		V[A] = T1 + T2;
	}

	for (u32 i = 0; i < REG_COUNT; ++i) {
		X[i] += V[i];
	}
}

const u8 *sha256digest::convert_digest_endian(u8 *out) const
{
	for (u32 i = 0; i < sizeof(m_digest); i += sizeof(u32)) {
		for (u32 j = 0; j < sizeof(u32); ++j) {
			out[i + 3 - j] = m_digest.u8[i + j];
		}
	}
	return out;
}

sha256digest::sha256digest( void )
{
	for (u32 i = 0; i < WORDS_PER_DIGEST; ++i) {
		m_digest.u32[i] = INITIAL_HASH_VALUES[i];
	}
}

sha256digest::sha256digest(const char *message) : sha256digest(message, u64(strlen(message)))
{}

sha256digest::sha256digest(const char *message, u64 byte_count) : sha256digest()
{
	u32  block_data[WORDS_PER_BLOCK]; // NOTE: Store this originally as u32 to force the compiler to align the memory on word boundry.
	u8  *block = (u8*)block_data;

	// Compute padding.
	const u64 ORIGINAL_MESSAGE_SIZE = byte_count;

	// Process every 512-bit block, except for partial or last one.
	if ((reinterpret_cast<const uintptr_t>(message) & (sizeof(u32) * CHAR_BIT - 1)) != 0) { // The message is not aligned so we need to bit block transfer it to an aligned block before processing (mainly to ensure functioning on ARM processors).
		while (byte_count >= BYTES_PER_BLOCK) {
			blit(message, block);
			process_block(block, m_digest.u32);
			message += BYTES_PER_BLOCK;
			byte_count -= BYTES_PER_BLOCK;
		}
	} else { // The message is aligned so we can process it directly without aligning it manually.*/
		const u8 *M = (const u8*)message;
		constexpr u32 BLOCK_WORDSIZE = BYTES_PER_BLOCK / sizeof(u32);
		while (byte_count >= BYTES_PER_BLOCK) {
			process_block(M, m_digest.u32);
			message += BYTES_PER_BLOCK;
			byte_count -= BYTES_PER_BLOCK;
			M += BLOCK_WORDSIZE;
		}
	}

	// The last block always needs to be processed manually since it always contains message size.
	blit(message, block, byte_count);

	// Store size (64 bits) of original message in bits at the end of the message
	u32 padding_size = BYTES_PER_BLOCK - (ORIGINAL_MESSAGE_SIZE % BYTES_PER_BLOCK);
	if (padding_size < sizeof(u64) + sizeof(u8)) { // Padding must at least fit a 64-bit number to denote message length in bits and one 8-bit number as a terminating 1-bit. If it does not, we add another block to process. Note that since we always work on bytes, not bits, the length of the terminating 1-bit is 8 bits, with a value of 0x80.
		padding_size += BYTES_PER_BLOCK;
	}

	// The message will always be padded in some way. Add a first '1' to the padding.
	block[byte_count] = PADDING_CONST;
	byte_count += padding_size;

	if (byte_count > BYTES_PER_BLOCK) { // Two blocks left to process.
		process_block(block, m_digest.u32);
		byte_count -= BYTES_PER_BLOCK;
		memset(block, 0, BYTES_PER_BLOCK - sizeof(u64));
	}

	// One block left to process. Store message size in big endian format.
	const u64 ORIGINAL_MESSAGE_BITSIZE = (ORIGINAL_MESSAGE_SIZE * CHAR_BIT);
	if (is_lil()) {
		for (u32 i = 0; i < sizeof(u64); ++i) {
			block[BYTES_PER_BLOCK - 1 - i] = reinterpret_cast<const 
			char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
		}
	} else {
		for (u32 i = 0; i < sizeof(u64); ++i) {
			block[BYTES_PER_BLOCK - sizeof(u64) + i] = reinterpret_cast<const char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
		}
	}
	process_block(block, m_digest.u32);
	byte_count -= BYTES_PER_BLOCK;

	// Clear sensitive data.
	memset(block, 0, BYTES_PER_BLOCK);
}

bool sha256digest::operator==(const sha256digest &r) const
{
	for (u32 i = 0; i < sizeof(m_digest) / sizeof(u32); ++i) {
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
	u8 digest_data[sizeof(m_digest)];
	const u8 *digest = is_lil() ? convert_digest_endian(digest_data) : m_digest.u8;
	for (u32 i = 0; i < sizeof(m_digest); ++i) {
		u8 b = digest[i];
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
	u8 digest_data[sizeof(m_digest)];
	const u8 *digest = is_lil() ? convert_digest_endian(digest_data) : m_digest.u8;
	for (u32 byte = 0; byte < sizeof(m_digest); ++byte) {
		for (u32 bit = 0; bit < BITS_PER_BYTE; ++bit) {
			out[byte * BITS_PER_BYTE + bit] = (digest[byte]  & (1 << (BITS_PER_BYTE - 1 - bit))) ? '1' : '0';
		}
	}
	return out;
}

std::string sha256(const char *message, u64 byte_count)
{
	return sha256digest(message, byte_count).hex();
}

std::string sha256(const char *message)
{
	return sha256digest(message).hex();
}
