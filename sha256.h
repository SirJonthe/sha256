/// @file
/// @author github.com/SirJonthe
/// @date 2022
/// @copyright Public domain. Derived from the U.S. NSA SHA256 Message-Digest Algorithm.
/// @license BSD-3-Clause

// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

#ifndef SHA256_H_INCLUDED__
#define SHA256_H_INCLUDED__

#include <string>
#include <cstdint>
#include <climits>
#include <cstring>


/// Processes messages of any length into a very unique identifyer with a length of 32 bytes. Functions by ingesting any number of messages via the 'ingest' function (alternatively via constructors and () operators) and finally outputting an SHA256 sum via the 'digest' function. New messages can be appended even after a digest has been generated.
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
	/// The output digest of data after SHA256 transformation.
	class sum
	{
		friend class sha256;
	private:
		union {
			uint32_t u32[WORDS_PER_DIGEST];
			uint8_t  u8[BYTES_PER_DIGEST];
		} m_sum;

	public:
		/// Compares l < r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator< (const sum &r) const;
		/// Compares l > r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator> (const sum &r) const;
		/// Compares l <= r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator<=(const sum &r) const;
		/// Compares l >= r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator>=(const sum &r) const;
		/// Compares l == r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator==(const sum &r) const;
		/// Compares l != r.
		///
		/// @param r the right-hand-side value to compare.
		///
		/// @returns the boolean result of the comparison
		bool operator!=(const sum &r) const;

		/// Returns the bytes of the digest.
		///
		/// @returns the pointer to the bytes in the digest.
		operator const uint8_t*( void ) const;
		/// Returns the bytes of the digest.
		///
		/// @returns the pointer to the bytes in the digest.
		operator uint8_t*( void );

		/// Prints the digest into a human-readable hexadeximal format stored in 'out' and returns 'out' incremented by the number of characters written. 
		char *sprint_hex(char *out) const;
		/// Prints the digest into a human-readable binary format stored in 'out' and returns 'out' incremented by the number of characters written.
		char *sprint_bin(char *out) const;

		/// Returns the human-readable hexadecimal format of the digest.
		///
		/// @param out the destination string of the print.
		///
		/// @returns the pointer to the location in the sprint at which printing stopped.
		std::string hex( void ) const;
		/// Returns the human-readable binary format of the digest.
		///
		/// @param out the destination string of the print.
		///
		/// @returns the pointer to the location in the sprint at which printing stopped.
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
	/// Returns a the right rotation of bits in 'l' by amount 'r'. Bits shifted out are shifted back in from the left.
	///
	/// @param l the value to rotate.
	/// @param r the number of iterations to rotate the value.
	///
	/// @returns the rotated bits.
	uint32_t rrot(uint32_t l, uint32_t r) const;
	/// Exclusive-or between three values.
	///
	/// @param a a value.
	/// @param b a value.
	/// @param c a value.
	///
	/// @returns the zored value.
	uint32_t zor(uint32_t a, uint32_t b, uint32_t c) const;
	/// Generic main lower case sigma function.
	///
	/// @param x a value.
	/// @param s1 the number of right rotations for the first step.
	/// @param s2 the number of right rotations for the second step.
	/// @param s3 the number of shifts for the third step.
	///
	/// @returns the lower case sigma.
	uint32_t sig(uint32_t x, uint32_t s1, uint32_t s2, uint32_t s3) const;
	/// Generic main upper case sigma function.
	///
	/// @param x a value.
	/// @param s1 the number of right rotations for the first step.
	/// @param s2 the number of right rotations for the second step.
	/// @param s3 the number of right rotations for the third step.
	///
	/// @returns the upper case sigma.
	uint32_t SIG(uint32_t x, uint32_t s1, uint32_t s2, uint32_t s3) const;
	/// Lower case sigma zero. Performs a transformation on one input value.
	///
	/// @param x the value.
	///
	/// @returns the lower case sigma zero.
	uint32_t sig0(uint32_t x) const;
	/// Lower case sigma one. Performs a transformation on one input value.
	///
	/// @param x a value.
	///
	/// @returns the lower case sigma one.
	uint32_t sig1(uint32_t x) const;
	/// Upper case sigma zero. Performs a transformation on one input value.
	///
	/// @param x a value.
	///
	/// @returns the upper case sigma zero.
	uint32_t SIG0(uint32_t x) const;
	/// Upper case sigma one. Performs a transformation on one input value.
	///
	/// @param x a value.
	///
	/// @returns the upper case sigma one.
	uint32_t SIG1(uint32_t x) const;
	/// Returns a bit array where the result is picked between 'y' and 'z' using 'x' as boolean selector. 1 picks from 'y', 0 picks from 'z'.
	///
	/// @param x a value.
	/// @param y a value.
	/// @param z a value.
	///
	/// @returns the choise bits.
	uint32_t choice(uint32_t x, uint32_t y, uint32_t z) const;
	/// Returns a bit array where the result is equal to the majority bit value for a given bit position between 'x', 'y', and 'z'.
	///
	/// @param x a value.
	/// @param y a value.
	/// @param z a value.
	///
	/// @returns the majority bits.
	uint32_t majority(uint32_t x, uint32_t y, uint32_t z) const;
	/// Bit-block transfer of 64 bytes from 'src' to 'dst'.
	///
	/// @param src the source to write.
	/// @param dst the destination to write to.
	void blit(const uint8_t *src, uint8_t *dst) const;
	/// Bit-block transfer of 'num' bytes from 'src' to 'dst'. Fills remaining 64-'num' bytes in 'dst' with zero-value.
	///
	/// @param src the source to write.
	/// @param dst the destination to write to.
	/// @param num the number of bytes to write.
	void blit(const uint8_t *src, uint8_t *dst, uint32_t num) const;
	/// Checks if the memory is aligned to a 4-byte boundary.
	///
	/// @param mem the memory location to check for alignment.
	///
	/// @returns boolean indicating true if the memory is 4-byte aligned, and false elsewise.
	bool is_aligned(const void *mem) const;
	/// Fills a message schedule with the contents from 'block' and calculates the remaining 48 words in the schedule.
	///
	/// @param block the pointer to the block from which to create a schedule from.
	/// @param schedule the destination of the output schedule.
	void create_schedule(const uint8_t *block, schedule_t &schedule) const;
	/// Processes a single message data block and transforms the digest values in 'X'.
	///
	/// @param block the pointer to the block to process.
	/// @param X the pointer to the digest to store the result of the process.
	void process_block(const uint8_t *block, uint32_t *X) const;
	/// Processes the remaining data in the block buffer so that a digest can be returned.
	///
	/// @param X the pointer to the digest to store the result of the process.
	void process_final_blocks(uint32_t *X) const;

public:
	/// Initialize digest to proper seed values.
	sha256( void );
	/// Ingest an initial message. Length is inferred from zero-terminator.
	///
	/// @param message pointer to a message to ingest.
	sha256(const char *message);
	/// Ingest an initial message. Explicit length.
	///
	/// @param message pointer to a message to ingest.
	/// @param byte_count the number of bytes in the message to ingest.
	sha256(const void *message, uint64_t byte_count);
	/// Clear out sensitive data.
	~sha256( void );

	/// Default copy constructor.
	sha256(const sha256&) = default;
	/// Default assignment operator.
	sha256 &operator=(const sha256&) = default;

	/// Ingest a message. Length is inferred from zero-terminator.
	///
	/// @param message pointer to a message to ingest.
	///
	/// @returns a reference to the modified data (self).
	sha256 &operator()(const char *message);
	/// Ingest a message. Explicit length.
	///
	/// @param message pointer to a message to ingest.
	/// @param byte_count the number of bytes in the message to ingest.
	///
	/// @returns a reference to the modified data (self).
	sha256 &operator()(const void *message, uint64_t byte_count);

	/// Returns a copy of current state with ingested message. Length is inferred from zero-terminator.
	///
	/// @param message pointer to the message to ingest.
	///
	/// @returns a modified sha256 incorporating the ingestion.
	sha256 operator()(const char *message) const;
	/// Returns a copy of current state with ingested message. Explicit length.
	///
	/// @param message pointer to the message to ingest.
	/// @param byte_count the number of bytes in the message to ingest.
	///
	/// @returns a modified sha256 incorporating the ingestion.
	sha256 operator()(const void *message, uint64_t byte_count) const;

	/// Ingest a message. Length is inferred from zero-terminator.
	///
	/// @param message pointer to a message to ingest.
	void ingest(const char *message);
	/// Ingest a message. Explicit length.
	///
	/// @param message pointer to a message to ingest.
	/// @param byte_count the number of bytes in the message to ingest.
	void ingest(const void *message, uint64_t byte_count);

	/// Returns the digest of all ingested messages.
	///
	/// @returns the digest.
	sum digest( void ) const;
	/// Implicitly converts state into digest of all ingested messages.
	///
	/// @returns the digest.
	operator sum( void ) const;
};

/// Returns the SHA256 digest of the input message as a human-readable hex string.
///
/// @param message pointer to a message to ingest.
///
/// @returns a string containing the human-readable hexadecimal digest of the message.
std::string sha256hex(const char *message);
/// Returns the SHA256 digest of the input message as a human-readable hex string.
///
/// @param message pointer to a message to ingest.
/// @param byte_count the number of bytes in the message to ingest.
///
/// @returns a string containing the human-readable hexadecimal digest of the message.
std::string sha256hex(const void *message, uint64_t byte_count);

#endif
