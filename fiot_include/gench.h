OctetString getClient_hello(RandomOctetString k_client);
void check_server_hello(OctetString hello);
OctetString gen_SHTS(RandomOctetString k_client, OctetString server_hello, OctetString client_hello, OctetString R1);
OctetString check_verify_frame(OctetString buf, OctetString eSHTK, OctetString iSHTK, OctetString c_hello, OctetString s_hello);
OctetString gen_CHTS(OctetString buf, OctetString hello, OctetString s_hello, OctetString R1, OctetString H3);
OctetString genVerify(OctetString H4);
OctetString genVerifyFrame(OctetString verify, OctetString eSHTK, OctetString iSHTK);
void make_session_keys(OctetString xQ, OctetString R2, OctetString H5, OctetString SATS, OctetString CATS);