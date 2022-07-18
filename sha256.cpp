#include "sha256.h"

// Typedefs to ease reading.
typedef uint8_t  u8;
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

bool sha256::sum::operator<(const sha256::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum); ++i) {
		if (m_sum.u8[i] >= r.m_sum.u8[i]) {
			return false;
		}
	}
	return true;
}

bool sha256::sum::operator>(const sha256::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum); ++i) {
		if (m_sum.u8[i] <= r.m_sum.u8[i]) {
			return false;
		}
	}
	return true;
}

bool sha256::sum::operator<=(const sha256::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum); ++i) {
		if (m_sum.u8[i] > r.m_sum.u8[i]) {
			return false;
		}
	}
	return true;
}

bool sha256::sum::operator>=(const sha256::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum); ++i) {
		if (m_sum.u8[i] < r.m_sum.u8[i]) {
			return false;
		}
	}
	return true;
}

bool sha256::sum::operator==(const sha256::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum); ++i) {
		if (m_sum.u8[i] != r.m_sum.u8[i]) {
			return false;
		}
	}
	return true;
}

bool sha256::sum::operator!=(const sha256::sum &r) const
{
	for (u32 i = 0; i < sizeof(m_sum); ++i) {
		if (m_sum.u8[i] == r.m_sum.u8[i]) {
			return false;
		}
	}
	return true;
}

sha256::sum::operator const u8*( void ) const
{
	return m_sum.u8;
}

sha256::sum::operator u8*( void )
{
	return m_sum.u8;
}

char *sha256::sum::sprint_hex(char *out) const
{
	static constexpr char DIGITS[] = "0123456789abcdef";
	for (u32 i = 0; i < sizeof(m_sum); ++i, out += 2) {
		u8 b = m_sum.u8[i];
		out[0] = DIGITS[b >> 4];
		out[1] = DIGITS[b & 15];
	}
	return out;
}

char *sha256::sum::sprint_bin(char *out) const
{
	for (u32 byte = 0; byte < sizeof(m_sum); ++byte) {
		for (u32 bit = 0; bit < CHAR_BIT; ++bit, ++out) {
			out[0] = (m_sum.u8[byte]  & (1 << (CHAR_BIT - 1 - bit))) ? '1' : '0';
		}
	}
	return out;
}

std::string sha256::sum::hex( void ) const
{
	static constexpr u64 SIZE = sizeof(m_sum) * 2;
	char str[SIZE];
	memset(str, 0, SIZE);
	sprint_hex(str);
	return std::string(str, size_t(SIZE));
}

std::string sha256::sum::bin( void ) const
{
	static constexpr u64 SIZE = sizeof(m_sum) * CHAR_BIT;
	char str[SIZE];
	memset(str, 0, SIZE);
	sprint_bin(str);
	return std::string(str, size_t(SIZE));
}

u32 sha256::rrot(u32 l, u32 r) const
{
	return (l >> r) | (l << (32 - r));
}

u32 sha256::zor(u32 a, u32 b, u32 c) const
{
	return a ^ b ^ c;
}

u32 sha256::sig(u32 x, u32 s1, u32 s2, u32 s3) const
{
	return zor(rrot(x, s1), rrot(x, s2), (x >> s3));
}

u32 sha256::SIG(u32 x, u32 s1, u32 s2, u32 s3) const
{
	return zor(rrot(x, s1), rrot(x, s2), rrot(x, s3));
}

u32 sha256::sig0(u32 x) const
{
	return sig(x, 7, 18, 3);
}

u32 sha256::sig1(u32 x) const
{
	return sig(x, 17, 19, 10);
}

u32 sha256::SIG0(u32 x) const
{
	return SIG(x, 2, 13, 22);
}

u32 sha256::SIG1(u32 x) const
{
	return SIG(x, 6, 11, 25);
}

u32 sha256::choice(u32 x, u32 y, u32 z) const
{
	return (x & y) ^ ((~x) & z);
}

u32 sha256::majority(u32 x, u32 y, u32 z) const
{
	return (x & y) ^ (x & z) ^ (y & z);
}

void sha256::blit(const u8 *src, u8 *dst) const
{
	memcpy(dst, src, BYTES_PER_BLOCK);
}

void sha256::blit(const u8 *src, u8 *dst, u32 num) const
{
	memcpy(dst, src, num);
	memset(dst + num, 0, BYTES_PER_BLOCK - num);
}

bool sha256::is_aligned(const void *mem) const
{
	return (reinterpret_cast<uintptr_t>(mem) & (sizeof(u32) - 1)) != 0;
}

void sha256::create_schedule(const u8 *block, schedule_t &schedule) const
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

void sha256::process_block(const u8 *block, u32 *X) const
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

void sha256::process_final_blocks(u32 *X) const
{
	u64 byte_count = m_block_size;
	union {
		u32 w32[WORDS_PER_BLOCK];
		u8  w8[BYTES_PER_BLOCK];
	} block;
	//u32 block_data[WORDS_PER_BLOCK];
	//u8 *block = reinterpret_cast<u8*>(block_data);

	// Store size (64 bits) of original message in bits at the end of the message
	u32 padding_size = BYTES_PER_BLOCK - (m_message_size % BYTES_PER_BLOCK);
	if (padding_size < sizeof(u64) + sizeof(u8)) { // Padding must at least fit a 64-bit number to denote message length in bits and one 8-bit number as a terminating 1-bit. If it does not, we add another block to process. Note that since we always work on bytes, not bits, the length of the terminating 1-bit is 8 bits, with a value of 0x80.
		padding_size += BYTES_PER_BLOCK;
	}

	// The message will always be padded in some way. Add a first '1' to the padding.
	memcpy(block.w8, m_block.u8, byte_count);
	block.w8[byte_count] = PADDING_CONST;
	memset(block.w8 + byte_count + 1, 0, BYTES_PER_BLOCK - (byte_count + 1));
	byte_count += padding_size;

	if (byte_count > BYTES_PER_BLOCK) { // Two blocks left to process.
		process_block(block.w8, X);
		memset(block.w8, 0, BYTES_PER_BLOCK - sizeof(u64));
	}

	// One block left to process. Store message size in big endian format.
	const u64 ORIGINAL_MESSAGE_BITSIZE = (m_message_size * CHAR_BIT);
	if (is_lil()) {
		for (u32 i = 0; i < sizeof(u64); ++i) {
			block.w8[BYTES_PER_BLOCK - 1 - i] = reinterpret_cast<const
			char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
		}
	} else {
		for (u32 i = 0; i < sizeof(u64); ++i) {
			block.w8[BYTES_PER_BLOCK - sizeof(u64) + i] = reinterpret_cast<const char*>(&ORIGINAL_MESSAGE_BITSIZE)[i];
		}
	}
	process_block(block.w8, X);
}

sha256::sha256( void ) : m_message_size(0), m_block_size(0)
{
	for (u32 i = 0; i < WORDS_PER_DIGEST; ++i) {
		m_state.u32[i] = INITIAL_HASH_VALUES[i];
	}
}

sha256::sha256(const char *message) : sha256()
{
	ingest(message);
}

sha256::sha256(const void *message, u64 byte_count) : sha256()
{
	ingest(message, byte_count);
}

sha256::~sha256( void )
{
	// Clear sensitive data.
	memset(m_block.u8, 0, sizeof(m_block.u8));
}

sha256 &sha256::operator()(const char *message)
{
	ingest(message);
	return *this;
}

sha256 &sha256::operator()(const void *message, u64 byte_count)
{
	ingest(message, byte_count);
	return *this;
}

sha256 sha256::operator()(const char *message) const
{
	return sha256(*this)(message);
}

sha256 sha256::operator()(const void *message, u64 byte_count) const
{
	return sha256(*this)(message, byte_count);
}

void sha256::ingest(const char *message)
{
	ingest(message, strlen(message));
}

void sha256::ingest(const void *message, u64 byte_count)
{	
	const u8 *msg = reinterpret_cast<const u8*>(message);
	m_message_size += byte_count;
	while (byte_count > 0) {
		u64 bytes_written = 0;
		if (m_block_size == 0 && byte_count >= BYTES_PER_BLOCK && is_aligned(msg)) {
			bytes_written = BYTES_PER_BLOCK;
			process_block(msg, m_state.u32);
		} else {
			const u64 BYTES_REMAINING = BYTES_PER_BLOCK - m_block_size;
			if (byte_count < BYTES_REMAINING) {
				bytes_written = byte_count;
				m_block_size += byte_count;
				blit(msg, m_block.u8, bytes_written);
			} else {
				bytes_written = BYTES_REMAINING;
				blit(msg, m_block.u8, bytes_written);
				process_block(m_block.u8, m_state.u32);
				m_block_size = 0;
			}
		}

		msg += bytes_written;
		byte_count -= bytes_written;
	}
}

sha256::sum sha256::digest( void ) const
{
	sum out;
	memcpy(out.m_sum.u8, m_state.u8, BYTES_PER_DIGEST);
	process_final_blocks(out.m_sum.u32);
	if (is_lil()) { // Convert endianess if necessary - digests should always be in the same format no matter what
		for (u32 i = 0; i < BYTES_PER_DIGEST; i += sizeof(u32)) {
			for (u32 j = 0; j < sizeof(u32) >> 1; ++j) {
				const u32 a = i + j;
				const u32 b = i + sizeof(u32) - j - 1;
				const u8 t = out.m_sum.u8[a];
				out.m_sum.u8[a] = out.m_sum.u8[b];
				out.m_sum.u8[b] = t;
			}
		}
	}
	return out;
}

sha256::operator sha256::sum( void ) const
{
	return digest();
}

std::string sha256hex(const void *message, u64 byte_count)
{
	return sha256(message, byte_count).digest().hex();
}

std::string sha256hex(const char *message)
{
	return sha256(message).digest().hex();
}
