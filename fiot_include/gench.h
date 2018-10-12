OctetString getClient_hello(RandomOctetString k_client);
void check_server_hello(OctetString hello);
OctetString gen_SHTS(RandomOctetString k_client, OctetString server_hello, OctetString client_hello);

