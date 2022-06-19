#ifndef SHA256_H_INCLUDED__
#define SHA256_H_INCLUDED__

#include <string>
#include <cstdint>
#include <climits>
#include <cstring>

// sha256digest
// The message digest using the SHA256 algorithm.
class sha256digest
{
private:
	// constants
	static constexpr uint32_t BITS_PER_BYTE      = 8;
	static constexpr uint32_t BITS_PER_DIGEST    = 256;
	static constexpr uint32_t BITS_PER_BLOCK     = 512;
	static constexpr uint32_t BYTES_PER_DIGEST   = BITS_PER_DIGEST / BITS_PER_BYTE;
	static constexpr uint32_t WORDS_PER_DIGEST   = BYTES_PER_DIGEST / sizeof(uint32_t);
	static constexpr uint32_t BYTES_PER_BLOCK    = BITS_PER_BLOCK / BITS_PER_BYTE;
	static constexpr uint32_t WORDS_PER_BLOCK    = BYTES_PER_BLOCK / sizeof(uint32_t);
	static constexpr uint32_t WORDS_PER_SCHEDULE = 64;
	static constexpr uint8_t  PADDING_CONST      = 1 << 7;

	// typedefs
	typedef uint32_t schedule_t[WORDS_PER_SCHEDULE];

private:
	union {
		uint8_t  u8[BYTES_PER_DIGEST];
		uint32_t u32[WORDS_PER_DIGEST];
	} m_digest; // The message digest.

private:
	// rrot
	// Returns a the right rotation of bits in 'l' by amount 'r'. Bits shifted out are shifted back in from the left.
	uint32_t rrot(uint32_t l, uint32_t r) const;
	// zor
	// Exclusive-or between three values.
	uint32_t zor(uint32_t a, uint32_t b, uint32_t c) const;
	// sig
	// Generic main lower case sigma function.
	uint32_t sig(uint32_t x, uint32_t s1, uint32_t s2, uint32_t s3) const;
	// SIG
	// Generic main upper case sigma function.
	uint32_t SIG(uint32_t x, uint32_t s1, uint32_t s2, uint32_t s3) const;
	// sig0
	// Lower case sigma zero. Performs a transformation on one input value.
	uint32_t sig0(uint32_t x) const;
	// sig1
	// Lower case sigma one. Performs a transformation on one input value.
	uint32_t sig1(uint32_t x) const;
	// SIG0
	// Upper case sigma zero. Performs a transformation on one input value.
	uint32_t SIG0(uint32_t x) const;
	// SIG1
	// Upper case sigma one. Performs a transformation on one input value.
	uint32_t SIG1(uint32_t x) const;
	// choice
	// Returns a bit array where the result is picked between 'y' and 'z' using 'x' as boolean selector. 1 picks from 'y', 0 picks from 'z'.
	uint32_t choice(uint32_t x, uint32_t y, uint32_t z) const;
	// majority
	// Returns a bit array where the result is equal to the majority bit value for a given bit position between 'x', 'y', and 'z'.
	uint32_t majority(uint32_t x, uint32_t y, uint32_t z) const;
	// blit
	// Bit-block transfer of 64 bytes from 'src' to 'dst'.
	void     blit(const char *src, uint8_t *dst) const;
	// blit
	// Bit-block transfer of 'num' bytes from 'src' to 'dst'. Fills remaining 64-'num' bytes in 'dst' with zero-value.
	void     blit(const char *src, uint8_t *dst, uint32_t num) const;
	// create_schedule
	// Fills a message schedule with the contents from 'block' and calculates the remaining 48 words in the schedule.
	void     create_schedule(const uint8_t *block, schedule_t &schedule) const;
	// process_block
	// Processes a single message data block and transforms the digest values in 'X'.
	void     process_block(const uint8_t *block, uint32_t *X) const;
	// convert_digest_endian
	// Converts bytes in digest to final endian and outputs them to 'digest'.
	void     convert_digest_endian(uint8_t *out) const;

public:
	// sha256digest
	// Initialize digest to proper seed values.
	sha256digest( void );
	// sha256digest
	// Create a message digest from the input message. Length is inferred from zero-terminator.
	explicit sha256digest(const char *message);
	// sha256digest
	// Create a message digest from the input message. Explicit length.
	sha256digest(const char *message, uint64_t byte_count);

	// sha256digest
	// Default copy constructor.
	sha256digest(const sha256digest&) = default;
	// operator=
	// Default assignment operator.
	sha256digest &operator=(const sha256digest&) = default;

	// operator==
	// Compares equality between digests.
	bool operator==(const sha256digest &r) const;
	// operator!=
	// Compares inequality between digests.
	bool operator!=(const sha256digest &r) const;

	// hex
	// Returns the digest as a human-readable hex string.
	std::string hex( void ) const;
	// bin
	// Returns the digest as a human-readable binary string.
	std::string bin( void ) const;
};

// sha256
// Returns the SHA256 digest of the input message as a human-readable hex string.
std::string sha256(const char *message, uint64_t byte_count);

// sha256
// Returns the SHA256 digest of the input message as a human-readable hex string.
std::string sha256(const char *input);

#endif
