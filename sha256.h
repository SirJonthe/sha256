#ifndef SHA256_H_INCLUDED__
#define SHA256_H_INCLUDED__

#include <string>
#include <cstdint>
#include <climits>
#include <cstring>

// sha256
// The main class used to ingest and process messages (on a byte basis) and eventually produce a digest (sum).
class sha256
{
private:
	// constants
	static constexpr uint32_t BITS_PER_BYTE      = CHAR_BIT;
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

public:
	// sum
	// The output digest of data after SHA256 transformation.
	class sum
	{
		friend class sha256;
	private:
		union {
			uint32_t u32[WORDS_PER_DIGEST];
			uint8_t  u8[BYTES_PER_DIGEST];
		} m_sum;

	public:
		// operator<
		// Compares l < r.
		bool operator< (const sum &r) const;
		// operator>
		// Compares l > r.
		bool operator> (const sum &r) const;
		// operator<=
		// Compares l <= r.
		bool operator<=(const sum &r) const;
		// operator>=
		// Compares l >= r.
		bool operator>=(const sum &r) const;
		// operator==
		// Compares l == r.
		bool operator==(const sum &r) const;
		// operator!=
		// Compares l != r.
		bool operator!=(const sum &r) const;

		// operator const uint8_t*
		// Returns the bytes of the digest.
		operator const uint8_t*( void ) const;
		// operator uint8_t*
		// Returns the bytes of the digest.
		operator uint8_t*( void );

		// sprint_hex
		// Prints the digest into a human-readable hexadeximal format stored in 'out' and returns 'out' incremented by the number of characters written. 
		char *sprint_hex(char *out) const;
		// sprint_bin
		// Prints the digest into a human-readable binary format stored in 'out' and returns 'out' incremented by the number of characters written.
		char *sprint_bin(char *out) const;

		// hex
		// Returns the human-readable hexadecimal format of the digest.
		std::string hex( void ) const;
		// bin
		// Returns the human-readable binary format of the digest.
		std::string bin( void ) const;
	};

private:
	union {
		uint32_t u32[WORDS_PER_DIGEST];
		uint8_t  u8[BYTES_PER_DIGEST];
	} m_state;
	union {
		uint32_t u32[WORDS_PER_BLOCK];
		uint8_t  u8[BYTES_PER_BLOCK];
	} m_block;
	uint64_t m_message_size;
	uint32_t m_block_size;

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
	void blit(const uint8_t *src, uint8_t *dst) const;
	// blit
	// Bit-block transfer of 'num' bytes from 'src' to 'dst'. Fills remaining 64-'num' bytes in 'dst' with zero-value.
	void blit(const uint8_t *src, uint8_t *dst, uint32_t num) const;
	// is_aligned
	// Checks if the memory is aligned to a 4-byte boundary.
	bool is_aligned(const void *mem) const;
	// create_schedule
	// Fills a message schedule with the contents from 'block' and calculates the remaining 48 words in the schedule.
	void create_schedule(const uint8_t *block, schedule_t &schedule) const;
	// process_block
	// Processes a single message data block and transforms the digest values in 'X'.
	void process_block(const uint8_t *block, uint32_t *X) const;
	// process_final_blocks
	// Processes the remaining data in the block buffer so that a digest can be returned.
	void process_final_blocks(uint32_t *X) const;

public:
	// sha256
	// Initialize digest to proper seed values.
	sha256( void );
	// sha256
	// Ingest an initial message. Length is inferred from zero-terminator.
	sha256(const char *message);
	// sha256
	// Ingest an initial message. Explicit length.
	sha256(const void *message, uint64_t byte_count);
	// ~sha256
	// Clear out sensitive data.
	~sha256( void );

	// sha256
	// Default copy constructor.
	sha256(const sha256&) = default;
	// operator=
	// Default assignment operator.
	sha256 &operator=(const sha256&) = default;

	// operator()
	// Ingest a message. Length is inferred from zero-terminator.
	sha256 &operator()(const char *message);
	// operator()
	// Ingest a message. Explicit length.
	sha256 &operator()(const void *message, uint64_t byte_count);

	// operator() const
	// Returns a copy of current state with ingested message. Length is inferred from zero-terminator.
	sha256 operator()(const char *message) const;
	// operator() const
	// Returns a copy of current state with ingested message. Explicit length.
	sha256 operator()(const void *message, uint64_t byte_count) const;

	// ingest
	// Ingest a message. Length is inferred from zero-terminator.
	void ingest(const char *message);
	// ingest
	// Ingest a message. Explicit length.
	void ingest(const void *message, uint64_t byte_count);

	// digest
	// Returns the digest of all ingested messages.
	sum digest( void ) const;
	// operator digest
	// Implicitly converts state into digest of all ingested messages.
	operator sum( void ) const;
};


// sha256hex
// Returns the SHA256 digest of the input message as a human-readable hex string.
std::string sha256hex(const char *message);

// sha256hex
// Returns the SHA256 digest of the input message as a human-readable hex string.
std::string sha256hex(const void *message, uint64_t byte_count);

#endif
