package rsapkcs1v15

const (
	bitsInByte = 8

	intOne = 1
	intTwo = 2

	int64One = int64(1)

	RSADefaultPublicExponent = 65537
	RSAKeyBitsMin            = 1024
	RSAKeyBitsDefault        = 2048

	pkcs1v15PrefixFirstByte  = 0x00
	pkcs1v15PrefixSecondByte = 0x01
	pkcs1v15SeparatorByte    = 0x00
	pkcs1v15PaddingByte      = 0xFF

	pkcs1v15MinPaddingLen = 8
	pkcs1v15OverheadBytes = 3
)

var (
	sha1DigestInfoPrefix = []byte{
		0x30, 0x21,
		0x30, 0x09,
		0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A,
		0x05, 0x00,
		0x04, 0x14,
	}
)
