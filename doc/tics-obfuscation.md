
TICS Obfuscation Methods
========================

The goals of the TICS Obfuscation Methods are to:

   1. To make credential secrets difficult to obtain.
   2. To be easy to implement without a crypto library.
   3. To prevent an attacker from being able to verify that the secret was
      correctly deobfuscated using only the data contained within the secret
      (unless the end user has specifically enabled verification).

The following obfuscation methods are currently supported:

   * clear text (0)
   * TICS Obfuscation Method 1 (16)
   * TICS Obfuscation Method 1 with verification SHA-512 hash (17)

The secret is either stored as unpacked and unobfuscated base32 encoded text
or as packed and obfuscated text.  Packed text consists of three fields
delimited using the ';' character.  The first field is the numeric decimal
string identifying the method used to obfuscate the secret.  The second field
may be empty or contains the decimal numeric string providing the length in
bytes of the obfuscated secret encoded using base64.  The third field consists
of the obfuscated secret encoded using base64. The following are examples of
the encoding formats for the secret "drowssap":

    # base32 secret
    MRZG653TONQXA===

    # packed secret using clear text/no obfuscation
    0;;ZHJvd3NzYXA=

    # packed length and secret using clear text/no obfuscation
    0;12;ZHJvd3NzYXA=

    # packed secret using obfuscation method 1
    16;;b+Rny5iEw+0ons3E0WAdT84D86/n2kfuBmDhIQAmOR9iWi5wLXEymoXSenbO7ZUHpq2C5O
    WU1B65JwiAHFXOzYWXHulcX6qsp5kjt0LRfoDdTAagxuHc6IKCecp/sNFOgeUOgnA7RT9vq3nl
    WqaSibBGsHDw2Iec89+rESOyFqQldspJ75FIBBE3YCIxe8eGeeC9wt+GQ++Ar4FWIWgiPmO5Xo
    ZxEBCeDOvQ1ZcTVcmJrcUIb6InLo6efuOQaOFalcURxQXAe7NH4FE9iqMgtC0VKvujWq774NaD
    d7v0/V6fvRHC9oZVLkCc+1IAOatpzKRImAfCsOVXW4r4p3cQlg==

    # packed secret using obfuscation method1 and SHA-512 hash
    17;;b+Rny5iEw+0ons3E0WAdT84D86/n2kfuBmDhIQAmOR9iWi5wLXEymoXSenbO7ZUHpq2C5O
    WU1B65JwiAHFXOzYWXHulcX6qsp5kjt0LRfoDdTAagxuHc6IKCecp/sNFOgeUOgnA7RT9vq3nl
    WqaSibBGsHDw2Iec89+rESOyFqQldspJ75FIBBE3YCIxe8eGeeC9wt+GQ++Ar4FWIWgiPmO5Xo
    ZxEBCeDOvQ1ZcTVcmJrcUIb6InLo6efuOQaOFalcURxQXAe7NH4FE9iqMgtC0VKvujWq774NaD
    d7v0/V6fvRHC9oZVLkCc+1IAOatpzKRImAfCsOVXW4r4p3cQlsb2uTx0odc8AVkuhr6uJwNO/O
    JVvK29grI032NMyoxL58BmjaRYlDahDbruwLNR2x0Q2bT2ahQcU+JFzzj5RUA=

    # packed length and secret using obfuscation method 1
    16;256;b+Rny5iEw+0ons3E0WAdT84D86/n2kfuBmDhIQAmOR9iWi5wLXEymoXSenbO7ZUHpq2
    C5OWU1B65JwiAHFXOzYWXHulcX6qsp5kjt0LRfoDdTAagxuHc6IKCecp/sNFOgeUOgnA7RT9vq
    3nlWqaSibBGsHDw2Iec89+rESOyFqQldspJ75FIBBE3YCIxe8eGeeC9wt+GQ++Ar4FWIWgiPmO
    5XoZxEBCeDOvQ1ZcTVcmJrcUIb6InLo6efuOQaOFalcURxQXAe7NH4FE9iqMgtC0VKvujWq774
    NaDd7v0/V6fvRHC9oZVLkCc+1IAOatpzKRImAfCsOVXW4r4p3cQlg==

    # encoded length and secret using obfuscation method 1 and SHA-512 hash
    17;320;b+Rny5iEw+0ons3E0WAdT84D86/n2kfuBmDhIQAmOR9iWi5wLXEymoXSenbO7ZUHpq2
    C5OWU1B65JwiAHFXOzYWXHulcX6qsp5kjt0LRfoDdTAagxuHc6IKCecp/sNFOgeUOgnA7RT9vq
    3nlWqaSibBGsHDw2Iec89+rESOyFqQldspJ75FIBBE3YCIxe8eGeeC9wt+GQ++Ar4FWIWgiPmO
    5XoZxEBCeDOvQ1ZcTVcmJrcUIb6InLo6efuOQaOFalcURxQXAe7NH4FE9iqMgtC0VKvujWq774
    NaDd7v0/V6fvRHC9oZVLkCc+1IAOatpzKRImAfCsOVXW4r4p3cQlsb2uTx0odc8AVkuhr6uJwN
    O/OJVvK29grI032NMyoxL58BmjaRYlDahDbruwLNR2x0Q2bT2ahQcU+JFzzj5RUA=


TICS Obfuscation Method 1
-------------------------

Method 1 uses blocks of 64 bytes to pack the secret and then uses psuedo
random numbers from HMAC-SHA-512 to obfuscate the secret. The packed secret
consists of the following parts:

   * 64 byte salt
   * 64 byte seed
   * Payload consisting of a multiple blocks of 64 bytes
   * An optional SHA-512 hash of the packed data

A packed secret can be represented as the following:

    +-------+-------+------...------+-------+
    | salt  | seed  |    payload    | hash  |
    +-------+-------+------...------+-------+

The 64 byte salt is stored in clear text and consists of 64 bytes of random
data.  The 64 byte seed is stored as obfuscated text and is used to determine
the offset of the data within the payload.

The 64 byte salt consists of 64 bytes of random data which is not obfuscated.
The 64 byte seed consists of 64 bytes of random data which is obfuscated. The
seed is used to calculate the data offset within the payload section. The
payload consists of padding of random data, the length of the secret data, the
secret data, and additional padding of random data. The optional SHA-512 hash
is the hash from the concatenation of the salt, seed, and payload sections.

The payload consists of the following parts:

   * Padding of random data.  The length of the padding is defined by the
     offset calculated from the seed.
   * Padded two bytes representing the length of the payload data in bytes.
   * The payload data.
   * Padding of random data extend the length of the paylaod to a multiple of
     64 bytes.

The length of the payload must be a multiple of 64 bytes and the payload must
be at least 64 bytes longer than the payload data. The length of the payload
must be decided prior to the encoding of the payload data length.  The
minimum length of the payload is determined by the length of the payload data.
The maximum length of the payload is not restricted by this specification.

The payload offset (amount of padding in the start of payload) is the modulo
of the sum of each byte of the seed and 62.  For example:

    seed = { byte0, byte1, byte2, ... byte63 };
    sum = byte0 + byte1 + byte2 + ... byte63;
    offset = sum % 62;

The length of the payload data is encoded as two bytes at the offset
calculated from the seed.  The most significant bits are random data and the
least significant bits represent the length of the data.  The mask used to
extract the length is calculated from the length of the payload minus 64 bytes
according to the following table:

          Payload Length Minus 64          Length Mask    Max Paylaod Data
             adjusted_length ==    64         0x003f            63 bytes
             adjusted_length ==   128         0x007f           127 bytes
      192 <= adjusted_length <=   256         0x00ff           255 bytes
      320 <= adjusted_length <=   512         0x01ff           511 bytes
      576 <= adjusted_length <=  1024         0x03ff          1023 bytes
     1088 <= adjusted_length <=  2048         0x07ff          2047 bytes
     2112 <= adjusted_length <=  4096         0x0fff          4095 bytes
     4160 <= adjusted_length <=  8192         0x1fff          8191 bytes
     8256 <= adjusted_length <= 16384         0x3fff         16383 bytes
    16448 <= adjusted_length <= 32768         0x7fff         32767 bytes
    32832 <= adjusted_length                  0xffff         65535 bytes

If the payload consists of 384 bytes, then the mask of 0x01ff is used to
extract the length of the data which must be 511 bytes or less.  Assuming that
the values 0x2b and 0x07 are at the offset, then using the mask of 0x01ff, the
length of the payload data would be 0x0107 (263) bytes:

    data_len == 0x0107 == 0x2b07 & 0x01ff

Following the length of the payload data is the payload data. The payload
is further padded with random data until the length of the payload reaches the
length used to calculate the mask of the payload data length.

To obfuscate the secret, the secret is split into 64 byte blocks.  Starting
with the second block of 64 bytes, each block is exclusive OR with the
HMAC-SHA-512 of the previous 64 byte blocks.  Assuming a 320 byte (5 blocks)
encoded secret:

    block0 // salt is unchanged
    block1 |= HMAC-SHA-512(key , block0) // seed
    block2 |= HMAC-SHA-512(key , block0-block1) // payload
    block3 |= HMAC-SHA-512(key , block0-block2) // payload
    block4 |= HMAC-SHA-512(key , block0-block3) // optional hash

The following is the metadata of an encoded and obfuscated secret:

    Secret Key:           "abcdefgh"
    Secret Data:          "drowssap"
    Secret Length:        320
    Payload Offset:       11
    Payload Mask:         0x003f
    Payload Data Pad/Len: 0x4208
    Payload Data Len Pad: 0x4200
    Payload Data Length:  0x0008 (8)

Hexdump of encoded and obfuscated secret (320 bytes):

    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000000  6f e4 67 cb 98 84 c3 ed 28 9e cd c4 d1 60 1d 4f  o.g.....(....`.O
    000010  ce 03 f3 af e7 da 47 ee 06 60 e1 21 00 26 39 1f  ......G..`.!.&9.
    000020  62 5a 2e 70 2d 71 32 9a 85 d2 7a 76 ce ed 95 07  bZ.p-q2...zv....
    000030  a6 ad 82 e4 e5 94 d4 1e b9 27 08 80 1c 55 ce cd  .........'...U..
    000040  85 97 1e e9 5c 5f aa ac a7 99 23 b7 42 d1 7e 80  ....\_....#.B.~.
    000050  dd 4c 06 a0 c6 e1 dc e8 82 82 79 ca 7f b0 d1 4e  .L........y....N
    000060  81 e5 0e 82 70 3b 45 3f 6f ab 79 e5 5a a6 92 89  ....p;E?o.y.Z...
    000070  b0 46 b0 70 f0 d8 87 9c f3 df ab 11 23 b2 16 a4  .F.p........#...
    000080  25 76 ca 49 ef 91 48 04 11 37 60 22 31 7b c7 86  %v.I..H..7`"1{..
    000090  79 e0 bd c2 df 86 43 ef 80 af 81 56 21 68 22 3e  y.....C....V!h">
    0000a0  63 b9 5e 86 71 10 10 9e 0c eb d0 d5 97 13 55 c9  c.^.q.........U.
    0000b0  89 ad c5 08 6f a2 27 2e 8e 9e 7e e3 90 68 e1 5a  ....o.'...~..h.Z
    0000c0  95 c5 11 c5 05 c0 7b b3 47 e0 51 3d 8a a3 20 b4  ......{.G.Q=.. .
    0000d0  2d 15 2a fb a3 5a ae fb e0 d6 83 77 bb f4 fd 5e  -.*..Z.....w...^
    0000e0  9f bd 11 c2 f6 86 55 2e 40 9c fb 52 00 39 ab 69  ......U.@..R.9.i
    0000f0  cc a4 48 98 07 c2 b0 e5 57 5b 8a f8 a7 77 10 96  ..H.....W[...w..
    000100  c6 f6 b9 3c 74 a1 d7 3c 01 59 2e 86 be ae 27 03  ...<t..<.Y....'.
    000110  4e fc e2 55 bc ad bd 82 b2 34 df 63 4c ca 8c 4b  N..U.....4.cL..K
    000120  e7 c0 66 8d a4 58 94 36 a1 0d ba ee c0 b3 51 db  ..f..X.6......Q.
    000130  1d 10 d9 b4 f6 6a 14 1c 53 e2 45 cf 38 f9 45 40  .....j..S.E.8.E@

Hexdump of same encoded secret without obfuscation (320 bytes):

    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000000  6f e4 67 cb 98 84 c3 ed 28 9e cd c4 d1 60 1d 4f  o.g.....(....`.O
    000010  ce 03 f3 af e7 da 47 ee 06 60 e1 21 00 26 39 1f  ......G..`.!.&9.
    000020  62 5a 2e 70 2d 71 32 9a 85 d2 7a 76 ce ed 95 07  bZ.p-q2...zv....
    000030  a6 ad 82 e4 e5 94 d4 1e b9 27 08 80 1c 55 ce cd  .........'...U..
    000040  35 a4 ee 8c 27 43 3f 4c fe 62 08 de 53 13 d8 f4  5...'C?L.b..S...
    000050  72 f1 e7 54 5b de 9e c6 12 01 1e ea 50 d7 f3 6b  r..T[.......P..k
    000060  72 61 f0 d2 72 c3 09 e6 f9 3a 63 28 af c8 a7 69  ra..r....:c(...i
    000070  b6 a3 fb 68 2b 29 c5 b7 eb 81 aa 69 25 07 9b 88  ...h+).....i%...
    000080  63 d8 48 b2 03 97 f9 31 55 50 83 42 08 64 72 6f  c.H....1UP.B.dro
    000090  77 73 73 61 70 6a c8 cc 5c 48 3d d0 77 d8 b0 d9  wssapj..\H=.w...
    0000a0  f7 ad fc 2d bf 7a 76 77 ed 0d 67 24 6f 9a d2 58  ...-.zvw..g$o..X
    0000b0  c2 a0 60 a9 a8 01 2a a3 33 02 e6 37 32 b7 22 c3  ..`...*.3..72.".
    0000c0  3e a9 f6 20 a3 15 1c f9 d4 7e a3 af 4b 00 a3 e1  >.. .....~..K...
    0000d0  3f 6d 30 0e 80 0a 78 d9 6f 02 8b bb 3b c5 4e 8c  ?m0...x.o...;.N.
    0000e0  6e 42 16 fd c8 77 a3 2f ae 4e 1c b7 00 f5 86 0a  nB...w./.N......
    0000f0  14 f4 63 e8 ad 35 1a 42 22 19 b7 f9 2a 16 c7 17  ..c..5.B"...*...
    000100  21 e9 74 47 13 f4 89 1a a8 84 42 f8 d9 b4 ee 69  !.tG......B....i
    000110  4a a1 1c 47 f4 54 e4 18 fb f6 39 54 4b 10 c5 1e  J..G.T....9TK...
    000120  9d 70 d6 45 bd 90 73 a2 de 76 9d e4 f5 2e 18 23  .p.E..s..v.....#
    000130  7d 25 2b 05 d3 86 ff 5b 6d fa 52 dd 67 bd 33 8c  }%+....[m.R.g.3.

Components of encoded Secret:

                   salt (64 bytes; 0x00000-0x0003f)
    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000000  6f e4 67 cb 98 84 c3 ed 28 9e cd c4 d1 60 1d 4f  o.g.....(....`.O
    000010  ce 03 f3 af e7 da 47 ee 06 60 e1 21 00 26 39 1f  ......G..`.!.&9.
    000020  62 5a 2e 70 2d 71 32 9a 85 d2 7a 76 ce ed 95 07  bZ.p-q2...zv....
    000030  a6 ad 82 e4 e5 94 d4 1e b9 27 08 80 1c 55 ce cd  .........'...U..

                offset seed (64 bytes; 0x00040-0x0007f)
    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000040  35 a4 ee 8c 27 43 3f 4c fe 62 08 de 53 13 d8 f4  5...'C?L.b..S...
    000050  72 f1 e7 54 5b de 9e c6 12 01 1e ea 50 d7 f3 6b  r..T[.......P..k
    000060  72 61 f0 d2 72 c3 09 e6 f9 3a 63 28 af c8 a7 69  ra..r....:c(...i
    000070  b6 a3 fb 68 2b 29 c5 b7 eb 81 aa 69 25 07 9b 88  ...h+).....i%...

               payload padding (11 bytes; 0x00080-0x0008a)
    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000080  63 d8 48 b2 03 97 f9 31 55 50 83  .  .  .  .  .  c.H....1UP......

             payload data length (2 bytes; 0x0008b-0x0008c)
    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000080   .  .  .  .  .  .  .  .  .  .  . 42 08  .  .  .  ...........B....

               payload data (8 bytes; 0x0008d-0x00094)
    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000080   .  .  .  .  .  .  .  .  .  .  .  .  . 64 72 6f  .............dro
    000090  77 73 73 61 70  .  .  .  .  .  .  .  .  .  .  .  wssap...........

              payload padding (107 bytes; 0x00095-0x000ff)
    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000090   .  .  .  .  . 6a c8 cc 5c 48 3d d0 77 d8 b0 d9  .....j..\H=.w...
    0000a0  f7 ad fc 2d bf 7a 76 77 ed 0d 67 24 6f 9a d2 58  ...-.zvw..g$o..X
    0000b0  c2 a0 60 a9 a8 01 2a a3 33 02 e6 37 32 b7 22 c3  ..`...*.3..72.".
    0000c0  3e a9 f6 20 a3 15 1c f9 d4 7e a3 af 4b 00 a3 e1  >.. .....~..K...
    0000d0  3f 6d 30 0e 80 0a 78 d9 6f 02 8b bb 3b c5 4e 8c  ?m0...x.o...;.N.
    0000e0  6e 42 16 fd c8 77 a3 2f ae 4e 1c b7 00 f5 86 0a  nB...w./.N......
    0000f0  14 f4 63 e8 ad 35 1a 42 22 19 b7 f9 2a 16 c7 17  ..c..5.B"...*...

             verification hash (64 bytes; 0x00100-0x0013f)
    offset   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
    000100  21 e9 74 47 13 f4 89 1a a8 84 42 f8 d9 b4 ee 69  !.tG......B....i
    000110  4a a1 1c 47 f4 54 e4 18 fb f6 39 54 4b 10 c5 1e  J..G.T....9TK...
    000120  9d 70 d6 45 bd 90 73 a2 de 76 9d e4 f5 2e 18 23  .p.E..s..v.....#
    000130  7d 25 2b 05 d3 86 ff 5b 6d fa 52 dd 67 bd 33 8c  }%+....[m.R.g.3.

