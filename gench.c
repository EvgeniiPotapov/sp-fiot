#include <stdio.h> 
#include <stdlib.h>
#include <string.h>

#include "krypt_include/libakrypt.h"
#include "krypt_include/ak_random.h"
#include "krypt_include/ak_buffer.h"
#include "krypt_include/ak_curves.h"
#include "krypt_include/ak_parameters.h"
#include "krypt_include/ak_mac.h"

#include "fiot_include/fiot_types.h"
#include "fiot_include/serialize_fiot.h"
#include "fiot_include/gench.h"

OctetString genClientHello(){
    ClientHelloMessage clientHello;

    clientHello.algorithm = hmac256ePSK;
    clientHello.idipsk.present = notPresent;
    clientHello.idepsk.present = isPresent;
    clientHello.idepsk.length = 8;
    clientHello.idepsk.id =  "Session0";

    struct random random;
    ak_random_create_lcg(&random);
    ak_buffer buf = ak_buffer_new_size(64);
    ak_buffer_set_random(buf, &random);
    ak_random_destroy(&random);
    memcpy(clientHello.random, buf->data, 32);
    RandomOctetString k_client;
    memcpy(k_client, buf->data + 32, 32);
    ak_buffer_delete(buf);

    clientHello.point.id = rfc4357_gost3410_2001_paramsetA;

    struct wpoint elliptic_point;
    ak_wpoint_pow(&elliptic_point,
                  (ak_wpoint) &id_rfc4357_gost3410_2001_paramsetA.point,
                  (ak_uint64 *)k_client,
                  ak_mpzn256_size,
                  (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);

    ak_wpoint_reduce( &elliptic_point, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);
    bzero(k_client, 32);
    clientHello.point.x = (OctetString) elliptic_point.x;
    clientHello.point.y = (OctetString) elliptic_point.y;
    clientHello.countOfExtensions = 0;
    OctetString serClientHello = malloc(1);
    serClientHelloMessage(&serClientHello, &clientHello);
    return serClientHello;
}

OctetString genHelloFrame(OctetString message){
    Frame helloFrame;

    helloFrame.tag = plainFrame;
    serLengthShortInt(helloFrame.length, 160);
    memset(helloFrame.number, 0x00, 5);
    helloFrame.type = clientHello;
    serLengthShortInt(helloFrame.meslen, 111);
    helloFrame.message = message;
    helloFrame.padding = "1234";
    helloFrame.icode.present = isPresent;
    helloFrame.icode.length = 32;
    helloFrame.icode.code = "DummyboxDummyboxDummyboxDummybox";
    OctetString serframe = malloc(1);
    serFrame(&serframe, &helloFrame);
    struct mac mctx;
    ak_mac_create_hmac_streebog256(&mctx);
    ak_mac_context_set_ptr(&mctx, "Session0CanBeTheOneToMakeAStable", 32);
    OctetString hmac = malloc(32);
    printf("data to hmac\n");
    for(int i=0;i<126;i++) printf("%.2X", serframe[i]);
    printf("\n");
    ak_mac_context_ptr( &mctx, serframe, 126, hmac);
    printf("hmac:\n");

    for(int i=0;i<32;i++) printf("%.2X", hmac[i]);
    printf("\n");

    ak_mac_destroy( &mctx );
    memcpy(&serframe[128], hmac, 32);

    free(hmac);
    return serframe;
}

OctetString getClient_hello(){
    ak_libakrypt_create(NULL);
    OctetString hello = genClientHello();
    OctetString serhello = genHelloFrame(hello);
    ak_libakrypt_destroy();
    return serhello;
}
