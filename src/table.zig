/// union of hashfunctions, it draws its values from the
/// table here https://raw.githubusercontent.com/multiformats/multicodec/master/table.csv
pub const HashFunction = enum(u63) {
    identity = 0x00,
    cidv1 = 0x01,
    cidv2 = 0x02,
    cidv3 = 0x03,
    ip4 = 0x04,
    tcp = 0x06,
    sha1 = 0x11,
    sha2_256 = 0x12,
    sha2_512 = 0x13,
    sha3_512 = 0x14,
    sha3_384 = 0x15,
    sha3_256 = 0x16,
    sha3_224 = 0x17,
    shake_128 = 0x18,
    shake_256 = 0x19,
    keccak_224 = 0x1a,
    keccak_256 = 0x1b,
    keccak_384 = 0x1c,
    keccak_512 = 0x1d,
    blake3 = 0x1e,
    sha2_384 = 0x20,
    dccp = 0x21,
    murmur3_x64_64 = 0x22,
    murmur3_32 = 0x23,
    ip6 = 0x29,
    ip6zone = 0x2a,
    ipcidr = 0x2b,
    path = 0x2f,
    multicodec = 0x30,
    multihash = 0x31,
    multiaddr = 0x32,
    multibase = 0x33,
    varsig = 0x34,
    dns = 0x35,
    dns4 = 0x36,
    dns6 = 0x37,
    dnsaddr = 0x38,
    protobuf = 0x50,
    cbor = 0x51,
    raw = 0x55,
    dbl_sha2_256 = 0x56,
    rlp = 0x60,
    bencode = 0x63,
    dag_pb = 0x70,
    dag_cbor = 0x71,
    libp2p_key = 0x72,
    git_raw = 0x78,
    torrent_info = 0x7b,
    torrent_file = 0x7c,
    leofcoin_block = 0x81,
    leofcoin_tx = 0x82,
    leofcoin_pr = 0x83,
    sctp = 0x84,
    dag_jose = 0x85,
    dag_cose = 0x86,
    lbry = 0x8c,
    eth_block = 0x90,
    eth_block_list = 0x91,
    eth_tx_trie = 0x92,
    eth_tx = 0x93,
    eth_tx_receipt_trie = 0x94,
    eth_tx_receipt = 0x95,
    eth_state_trie = 0x96,
    eth_account_snapshot = 0x97,
    eth_storage_trie = 0x98,
    eth_receipt_log_trie = 0x99,
    eth_receipt_log = 0x9a,
    aes_128 = 0xa0,
    aes_192 = 0xa1,
    aes_256 = 0xa2,
    chacha_128 = 0xa3,
    chacha_256 = 0xa4,
    bitcoin_block = 0xb0,
    bitcoin_tx = 0xb1,
    bitcoin_witness_commitment = 0xb2,
    zcash_block = 0xc0,
    zcash_tx = 0xc1,
    caip_50 = 0xca,
    streamid = 0xce,
    stellar_block = 0xd0,
    stellar_tx = 0xd1,
    md4 = 0xd4,
    md5 = 0xd5,
    decred_block = 0xe0,
    decred_tx = 0xe1,
    ipld = 0xe2,
    ipfs = 0xe3,
    swarm = 0xe4,
    ipns = 0xe5,
    zeronet = 0xe6,
    secp256k1_pub = 0xe7,
    dnslink = 0xe8,
    bls12_381_g1_pub = 0xea,
    bls12_381_g2_pub = 0xeb,
    x25519_pub = 0xec,
    ed25519_pub = 0xed,
    bls12_381_g1g2_pub = 0xee,
    sr25519_pub = 0xef,
    dash_block = 0xf0,
    dash_tx = 0xf1,
    swarm_manifest = 0xfa,
    swarm_feed = 0xfb,
    beeson = 0xfc,
    udp = 0x0111,
    p2p_webrtc_star = 0x0113,
    p2p_webrtc_direct = 0x0114,
    p2p_stardust = 0x0115,
    webrtc_direct = 0x0118,
    webrtc = 0x0119,
    p2p_circuit = 0x0122,
    dag_json = 0x0129,
    udt = 0x012d,
    utp = 0x012e,
    crc32 = 0x0132,
    crc64_ecma = 0x0164,
    unix = 0x0190,
    thread = 0x0196,
    p2p = 0x01a5,
    https = 0x01bb,
    onion = 0x01bc,
    onion3 = 0x01bd,
    garlic64 = 0x01be,
    garlic32 = 0x01bf,
    tls = 0x01c0,
    sni = 0x01c1,
    noise = 0x01c6,
    shs = 0x01c8,
    quic = 0x01cc,
    quic_v1 = 0x01cd,
    webtransport = 0x01d1,
    certhash = 0x01d2,
    ws = 0x01dd,
    wss = 0x01de,
    p2p_websocket_star = 0x01df,
    http = 0x01e0,
    swhid_1_snp = 0x01f0,
    json = 0x0200,
    messagepack = 0x0201,
    car = 0x0202,
    ipns_record = 0x0300,
    libp2p_peer_record = 0x0301,
    libp2p_relay_rsvp = 0x0302,
    memorytransport = 0x0309,
    car_index_sorted = 0x0400,
    car_multihash_index_sorted = 0x0401,
    transport_bitswap = 0x0900,
    transport_graphsync_filecoinv1 = 0x0910,
    transport_ipfs_gateway_http = 0x0920,
    multidid = 0x0d1d,
    sha2_256_trunc254_padded = 0x1012,
    sha2_224 = 0x1013,
    sha2_512_224 = 0x1014,
    sha2_512_256 = 0x1015,
    murmur3_x64_128 = 0x1022,
    ripemd_128 = 0x1052,
    ripemd_160 = 0x1053,
    ripemd_256 = 0x1054,
    ripemd_320 = 0x1055,
    x11 = 0x1100,
    p256_pub = 0x1200,
    p384_pub = 0x1201,
    p521_pub = 0x1202,
    ed448_pub = 0x1203,
    x448_pub = 0x1204,
    rsa_pub = 0x1205,
    sm2_pub = 0x1206,
    ed25519_priv = 0x1300,
    secp256k1_priv = 0x1301,
    x25519_priv = 0x1302,
    sr25519_priv = 0x1303,
    rsa_priv = 0x1305,
    p256_priv = 0x1306,
    p384_priv = 0x1307,
    p521_priv = 0x1308,
    bls12_381_g1_priv = 0x1309,
    bls12_381_g2_priv = 0x130a,
    bls12_381_g1g2_priv = 0x130b,
    kangarootwelve = 0x1d01,
    aes_gcm_256 = 0x2000,
    silverpine = 0x3f42,
    sm3_256 = 0x534d,
    sha256a = 0x7012,
    blake2b_8 = 0xb201,
    blake2b_16 = 0xb202,
    blake2b_24 = 0xb203,
    blake2b_32 = 0xb204,
    blake2b_40 = 0xb205,
    blake2b_48 = 0xb206,
    blake2b_56 = 0xb207,
    blake2b_64 = 0xb208,
    blake2b_72 = 0xb209,
    blake2b_80 = 0xb20a,
    blake2b_88 = 0xb20b,
    blake2b_96 = 0xb20c,
    blake2b_104 = 0xb20d,
    blake2b_112 = 0xb20e,
    blake2b_120 = 0xb20f,
    blake2b_128 = 0xb210,
    blake2b_136 = 0xb211,
    blake2b_144 = 0xb212,
    blake2b_152 = 0xb213,
    blake2b_160 = 0xb214,
    blake2b_168 = 0xb215,
    blake2b_176 = 0xb216,
    blake2b_184 = 0xb217,
    blake2b_192 = 0xb218,
    blake2b_200 = 0xb219,
    blake2b_208 = 0xb21a,
    blake2b_216 = 0xb21b,
    blake2b_224 = 0xb21c,
    blake2b_232 = 0xb21d,
    blake2b_240 = 0xb21e,
    blake2b_248 = 0xb21f,
    blake2b_256 = 0xb220,
    blake2b_264 = 0xb221,
    blake2b_272 = 0xb222,
    blake2b_280 = 0xb223,
    blake2b_288 = 0xb224,
    blake2b_296 = 0xb225,
    blake2b_304 = 0xb226,
    blake2b_312 = 0xb227,
    blake2b_320 = 0xb228,
    blake2b_328 = 0xb229,
    blake2b_336 = 0xb22a,
    blake2b_344 = 0xb22b,
    blake2b_352 = 0xb22c,
    blake2b_360 = 0xb22d,
    blake2b_368 = 0xb22e,
    blake2b_376 = 0xb22f,
    blake2b_384 = 0xb230,
    blake2b_392 = 0xb231,
    blake2b_400 = 0xb232,
    blake2b_408 = 0xb233,
    blake2b_416 = 0xb234,
    blake2b_424 = 0xb235,
    blake2b_432 = 0xb236,
    blake2b_440 = 0xb237,
    blake2b_448 = 0xb238,
    blake2b_456 = 0xb239,
    blake2b_464 = 0xb23a,
    blake2b_472 = 0xb23b,
    blake2b_480 = 0xb23c,
    blake2b_488 = 0xb23d,
    blake2b_496 = 0xb23e,
    blake2b_504 = 0xb23f,
    blake2b_512 = 0xb240,
    blake2s_8 = 0xb241,
    blake2s_16 = 0xb242,
    blake2s_24 = 0xb243,
    blake2s_32 = 0xb244,
    blake2s_40 = 0xb245,
    blake2s_48 = 0xb246,
    blake2s_56 = 0xb247,
    blake2s_64 = 0xb248,
    blake2s_72 = 0xb249,
    blake2s_80 = 0xb24a,
    blake2s_88 = 0xb24b,
    blake2s_96 = 0xb24c,
    blake2s_104 = 0xb24d,
    blake2s_112 = 0xb24e,
    blake2s_120 = 0xb24f,
    blake2s_128 = 0xb250,
    blake2s_136 = 0xb251,
    blake2s_144 = 0xb252,
    blake2s_152 = 0xb253,
    blake2s_160 = 0xb254,
    blake2s_168 = 0xb255,
    blake2s_176 = 0xb256,
    blake2s_184 = 0xb257,
    blake2s_192 = 0xb258,
    blake2s_200 = 0xb259,
    blake2s_208 = 0xb25a,
    blake2s_216 = 0xb25b,
    blake2s_224 = 0xb25c,
    blake2s_232 = 0xb25d,
    blake2s_240 = 0xb25e,
    blake2s_248 = 0xb25f,
    blake2s_256 = 0xb260,
    skein256_8 = 0xb301,
    skein256_16 = 0xb302,
    skein256_24 = 0xb303,
    skein256_32 = 0xb304,
    skein256_40 = 0xb305,
    skein256_48 = 0xb306,
    skein256_56 = 0xb307,
    skein256_64 = 0xb308,
    skein256_72 = 0xb309,
    skein256_80 = 0xb30a,
    skein256_88 = 0xb30b,
    skein256_96 = 0xb30c,
    skein256_104 = 0xb30d,
    skein256_112 = 0xb30e,
    skein256_120 = 0xb30f,
    skein256_128 = 0xb310,
    skein256_136 = 0xb311,
    skein256_144 = 0xb312,
    skein256_152 = 0xb313,
    skein256_160 = 0xb314,
    skein256_168 = 0xb315,
    skein256_176 = 0xb316,
    skein256_184 = 0xb317,
    skein256_192 = 0xb318,
    skein256_200 = 0xb319,
    skein256_208 = 0xb31a,
    skein256_216 = 0xb31b,
    skein256_224 = 0xb31c,
    skein256_232 = 0xb31d,
    skein256_240 = 0xb31e,
    skein256_248 = 0xb31f,
    skein256_256 = 0xb320,
    skein512_8 = 0xb321,
    skein512_16 = 0xb322,
    skein512_24 = 0xb323,
    skein512_32 = 0xb324,
    skein512_40 = 0xb325,
    skein512_48 = 0xb326,
    skein512_56 = 0xb327,
    skein512_64 = 0xb328,
    skein512_72 = 0xb329,
    skein512_80 = 0xb32a,
    skein512_88 = 0xb32b,
    skein512_96 = 0xb32c,
    skein512_104 = 0xb32d,
    skein512_112 = 0xb32e,
    skein512_120 = 0xb32f,
    skein512_128 = 0xb330,
    skein512_136 = 0xb331,
    skein512_144 = 0xb332,
    skein512_152 = 0xb333,
    skein512_160 = 0xb334,
    skein512_168 = 0xb335,
    skein512_176 = 0xb336,
    skein512_184 = 0xb337,
    skein512_192 = 0xb338,
    skein512_200 = 0xb339,
    skein512_208 = 0xb33a,
    skein512_216 = 0xb33b,
    skein512_224 = 0xb33c,
    skein512_232 = 0xb33d,
    skein512_240 = 0xb33e,
    skein512_248 = 0xb33f,
    skein512_256 = 0xb340,
    skein512_264 = 0xb341,
    skein512_272 = 0xb342,
    skein512_280 = 0xb343,
    skein512_288 = 0xb344,
    skein512_296 = 0xb345,
    skein512_304 = 0xb346,
    skein512_312 = 0xb347,
    skein512_320 = 0xb348,
    skein512_328 = 0xb349,
    skein512_336 = 0xb34a,
    skein512_344 = 0xb34b,
    skein512_352 = 0xb34c,
    skein512_360 = 0xb34d,
    skein512_368 = 0xb34e,
    skein512_376 = 0xb34f,
    skein512_384 = 0xb350,
    skein512_392 = 0xb351,
    skein512_400 = 0xb352,
    skein512_408 = 0xb353,
    skein512_416 = 0xb354,
    skein512_424 = 0xb355,
    skein512_432 = 0xb356,
    skein512_440 = 0xb357,
    skein512_448 = 0xb358,
    skein512_456 = 0xb359,
    skein512_464 = 0xb35a,
    skein512_472 = 0xb35b,
    skein512_480 = 0xb35c,
    skein512_488 = 0xb35d,
    skein512_496 = 0xb35e,
    skein512_504 = 0xb35f,
    skein512_512 = 0xb360,
    skein1024_8 = 0xb361,
    skein1024_16 = 0xb362,
    skein1024_24 = 0xb363,
    skein1024_32 = 0xb364,
    skein1024_40 = 0xb365,
    skein1024_48 = 0xb366,
    skein1024_56 = 0xb367,
    skein1024_64 = 0xb368,
    skein1024_72 = 0xb369,
    skein1024_80 = 0xb36a,
    skein1024_88 = 0xb36b,
    skein1024_96 = 0xb36c,
    skein1024_104 = 0xb36d,
    skein1024_112 = 0xb36e,
    skein1024_120 = 0xb36f,
    skein1024_128 = 0xb370,
    skein1024_136 = 0xb371,
    skein1024_144 = 0xb372,
    skein1024_152 = 0xb373,
    skein1024_160 = 0xb374,
    skein1024_168 = 0xb375,
    skein1024_176 = 0xb376,
    skein1024_184 = 0xb377,
    skein1024_192 = 0xb378,
    skein1024_200 = 0xb379,
    skein1024_208 = 0xb37a,
    skein1024_216 = 0xb37b,
    skein1024_224 = 0xb37c,
    skein1024_232 = 0xb37d,
    skein1024_240 = 0xb37e,
    skein1024_248 = 0xb37f,
    skein1024_256 = 0xb380,
    skein1024_264 = 0xb381,
    skein1024_272 = 0xb382,
    skein1024_280 = 0xb383,
    skein1024_288 = 0xb384,
    skein1024_296 = 0xb385,
    skein1024_304 = 0xb386,
    skein1024_312 = 0xb387,
    skein1024_320 = 0xb388,
    skein1024_328 = 0xb389,
    skein1024_336 = 0xb38a,
    skein1024_344 = 0xb38b,
    skein1024_352 = 0xb38c,
    skein1024_360 = 0xb38d,
    skein1024_368 = 0xb38e,
    skein1024_376 = 0xb38f,
    skein1024_384 = 0xb390,
    skein1024_392 = 0xb391,
    skein1024_400 = 0xb392,
    skein1024_408 = 0xb393,
    skein1024_416 = 0xb394,
    skein1024_424 = 0xb395,
    skein1024_432 = 0xb396,
    skein1024_440 = 0xb397,
    skein1024_448 = 0xb398,
    skein1024_456 = 0xb399,
    skein1024_464 = 0xb39a,
    skein1024_472 = 0xb39b,
    skein1024_480 = 0xb39c,
    skein1024_488 = 0xb39d,
    skein1024_496 = 0xb39e,
    skein1024_504 = 0xb39f,
    skein1024_512 = 0xb3a0,
    skein1024_520 = 0xb3a1,
    skein1024_528 = 0xb3a2,
    skein1024_536 = 0xb3a3,
    skein1024_544 = 0xb3a4,
    skein1024_552 = 0xb3a5,
    skein1024_560 = 0xb3a6,
    skein1024_568 = 0xb3a7,
    skein1024_576 = 0xb3a8,
    skein1024_584 = 0xb3a9,
    skein1024_592 = 0xb3aa,
    skein1024_600 = 0xb3ab,
    skein1024_608 = 0xb3ac,
    skein1024_616 = 0xb3ad,
    skein1024_624 = 0xb3ae,
    skein1024_632 = 0xb3af,
    skein1024_640 = 0xb3b0,
    skein1024_648 = 0xb3b1,
    skein1024_656 = 0xb3b2,
    skein1024_664 = 0xb3b3,
    skein1024_672 = 0xb3b4,
    skein1024_680 = 0xb3b5,
    skein1024_688 = 0xb3b6,
    skein1024_696 = 0xb3b7,
    skein1024_704 = 0xb3b8,
    skein1024_712 = 0xb3b9,
    skein1024_720 = 0xb3ba,
    skein1024_728 = 0xb3bb,
    skein1024_736 = 0xb3bc,
    skein1024_744 = 0xb3bd,
    skein1024_752 = 0xb3be,
    skein1024_760 = 0xb3bf,
    skein1024_768 = 0xb3c0,
    skein1024_776 = 0xb3c1,
    skein1024_784 = 0xb3c2,
    skein1024_792 = 0xb3c3,
    skein1024_800 = 0xb3c4,
    skein1024_808 = 0xb3c5,
    skein1024_816 = 0xb3c6,
    skein1024_824 = 0xb3c7,
    skein1024_832 = 0xb3c8,
    skein1024_840 = 0xb3c9,
    skein1024_848 = 0xb3ca,
    skein1024_856 = 0xb3cb,
    skein1024_864 = 0xb3cc,
    skein1024_872 = 0xb3cd,
    skein1024_880 = 0xb3ce,
    skein1024_888 = 0xb3cf,
    skein1024_896 = 0xb3d0,
    skein1024_904 = 0xb3d1,
    skein1024_912 = 0xb3d2,
    skein1024_920 = 0xb3d3,
    skein1024_928 = 0xb3d4,
    skein1024_936 = 0xb3d5,
    skein1024_944 = 0xb3d6,
    skein1024_952 = 0xb3d7,
    skein1024_960 = 0xb3d8,
    skein1024_968 = 0xb3d9,
    skein1024_976 = 0xb3da,
    skein1024_984 = 0xb3db,
    skein1024_992 = 0xb3dc,
    skein1024_1000 = 0xb3dd,
    skein1024_1008 = 0xb3de,
    skein1024_1016 = 0xb3df,
    skein1024_1024 = 0xb3e0,
    xxh_32 = 0xb3e1,
    xxh_64 = 0xb3e2,
    xxh3_64 = 0xb3e3,
    xxh3_128 = 0xb3e4,
    poseidon_bls12_381_a2_fc1 = 0xb401,
    poseidon_bls12_381_a2_fc1_sc = 0xb402,
    rdfc_1 = 0xb403,
    ssz = 0xb501,
    ssz_sha2_256_bmt = 0xb502,
    sha2_256_chunked = 0xb510,
    json_jcs = 0xb601,
    iscc = 0xcc01,
    zeroxcert_imprint_256 = 0xce11,
    nonstandard_sig = 0xd000,
    es256k = 0xd0e7,
    bls_12381_g1_sig = 0xd0ea,
    bls_12381_g2_sig = 0xd0eb,
    eddsa = 0xd0ed,
    eip_191 = 0xd191,
    jwk_jcs_pub = 0xeb51,
    fil_commitment_unsealed = 0xf101,
    fil_commitment_sealed = 0xf102,
    plaintextv2 = 0x706c61,
    holochain_adr_v0 = 0x807124,
    holochain_adr_v1 = 0x817124,
    holochain_key_v0 = 0x947124,
    holochain_key_v1 = 0x957124,
    holochain_sig_v0 = 0xa27124,
    holochain_sig_v1 = 0xa37124,
    skynet_ns = 0xb19910,
    arweave_ns = 0xb29910,
    subspace_ns = 0xb39910,
    kumandra_ns = 0xb49910,
    es256 = 0xd01200,
    es284 = 0xd01201,
    es512 = 0xd01202,
    rs256 = 0xd01205,
    scion = 0xd02000,
};
