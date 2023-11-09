/* sqrt(-1) */
static const fe25519 fe25519_sqrtm1 = { -32595792, -7943725, 9377950,
					3500415,   12389472, -272473,
					-25146209, -2005654, 326686,
					11406482 };

/* sqrt(-486664) */
static const fe25519 ed25519_sqrtam2 = { -12222970, -8312128,  -11511410,
					 9067497,   -15300785, -241793,
					 25456130,  14121551,  -12187136,
					 3972024 };

/* 37095705934669439343138083508754565189542113879843219016388785533085940283555 */
static const fe25519 ed25519_d = { -10913610, 13857413, -15372611, 6949391,
				   114729,    -8787816, -6275908,  -3247719,
				   -18696448, -12055116 };

/* 2 * d =
 * 16295367250680780974490674513165176452449235426866156013048779062215315747161
 */
static const fe25519 ed25519_d2 = { -21827239, -5839606, -30745221, 13898782,
				    229458,    15978800, -12551817, -6495438,
				    29715968,  9444199 };

/* A = 486662 */
#define ed25519_A_32 486662
static const fe25519 ed25519_A = { ed25519_A_32, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/* sqrt(ad - 1) with a = -1 (mod p) */
static const fe25519 ed25519_sqrtadm1 = { 24849947,  -153582,	-23613485,
					  6347715,   -21072328, -667138,
					  -25271143, -15367704, -870347,
					  14525639 };

/* 1 / sqrt(a - d) */
static const fe25519 ed25519_invsqrtamd = { 6111485,  4156064,	 -27798727,
					    12243468, -25904040, 120897,
					    20826367, -7060776,	 6093568,
					    -1986012 };

/* 1 - d ^ 2 */
static const fe25519 ed25519_onemsqd = { 6275446,   -16617371, -22938544,
					 -3773710,  11667077,  7397348,
					 -27922721, 1766195,   -24433858,
					 672203 };

/* (d - 1) ^ 2 */
static const fe25519 ed25519_sqdmone = { 15551795,  -11097455, -13425098,
					 -10125071, -11896535, 10178284,
					 -26634327, 4729244,   -5282110,
					 -10116402 };