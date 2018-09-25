/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*  ak_mac.c                                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>
 #include <ak_compress.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция очищает контекст секретного ключа алгоритма выработки имитовставки hmac, а также
    проверяет ресурс ключа.

    @param ctx контекст ключа алгоритма hmac
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hmac_clean( ak_pointer ctx )
{
  ak_hmac hctx = ( ak_hmac ) ctx;
  int error = ak_error_ok;
  size_t idx = 0, count = 0;

  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&ak_skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );

  if( hctx->key.resource.counter <= 1 ) return ak_error_message( ak_error_resource_counter,
                                            __func__, "using hmac key context with low resource" );
                         /* нам надо два раза использовать ключ => ресурс должен быть не менее 2х */

 /* инициализируем начальное состояние контекста хеширования */
  if(( error = hctx->ctx.clean( &hctx->ctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong cleaning of hash function context" );

 /* цикл по количеству 8-ми байтных блоков в ключе */
  count = hctx->key.key.size >> 3;
  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= 0x3636363636363636LL;
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= ((ak_uint64 *)hctx->key.mask.data)[idx];
  }
  if(( error =
         hctx->ctx.update( &hctx->ctx, hctx->key.key.data, hctx->key.key.size )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid 1st step iteration for hmac key context" );

  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= ((ak_uint64 *)hctx->key.mask.data)[idx];
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= 0x3636363636363636LL;
  }
  hctx->key.remask( &hctx->key );
  hctx->key.resource.counter--; /* мы использовали ключ один раз */

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция обновляет текущее состояние контекста алгоритма выработки имитовставки hmac.

    @param ctx контекст ключа алгоритма hmac
    @param data указатель на обрабатываемые данные
    @param size длина обрабатываемых данных (в байтах); длина должна быть кратна длине блока
    обрабатываемых данных используемой функции хеширования
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hmac_update( ak_pointer ctx, const ak_pointer data, const size_t size )
{
  ak_hmac hctx = ( ak_hmac ) ctx;

  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to hmac key context" );
  if( !size ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                      "using zero length for authenticated data" );
  if( size%hctx->ctx.bsize ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                  "using data with wrong length" );
 /* проверяем наличие ключа и его ресурс */
  if( !((hctx->key.flags)&ak_skey_flag_set_key )) return ak_error_message( ak_error_key_value,
                                               __func__ , "using hmac key with unassigned value" );
  if( hctx->key.resource.counter <= 0 ) return ak_error_message( ak_error_resource_counter,
                                            __func__, "using hmac key context with low resource" );

  return hctx->ctx.update( &hctx->ctx, data, size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция завершает вычисление алгоритма выработки имитовставки hmac.

    @param ctx контекст ключа алгоритма hmac
    @param data блок входных данных; длина блока должна быть менее, чем блина блока
           обрабатываемых данных для используемой функции хеширования
    @param size длина блока обрабатываемых данных
    @param out указатель на область памяти, куда будет помещен результат; если out равен NULL,
           то создается новый буффер, в который помещается результат.
    @return если out равен NULL, то возвращается указатель на созданный буффер. В противном случае
           возвращается NULL. В случае возникновения ошибки возывращается NULL. Код ошибки может
           быть получен c помощью вызова функции ak_error_get_value().                             */
/* ----------------------------------------------------------------------------------------------- */
 static ak_buffer ak_hmac_finalize( ak_pointer ctx, const ak_pointer data,
                                                               const size_t size, ak_pointer out )
{
#define temporary_size_value  (128)

  int error = ak_error_ok;
  ak_buffer result = NULL;
  size_t idx = 0, count = 0;
  ak_uint8 temporary[temporary_size_value]; /* буфер для хранения промежуточных результатов */
  ak_hmac hctx = ( ak_hmac ) ctx;

 /* выполняем проверки */
  if( hctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hmac context" );
    return NULL;
  }
 /* ограничение в связи с константным размером временного буффера */
  if( hctx->ctx.hsize > temporary_size_value ) {
    ak_error_message( ak_error_wrong_length,
                  __func__, "using a hash context with unsupported large integrity code size" );
    return NULL;
  }
  if( size >= hctx->ctx.bsize ) {
    ak_error_message( ak_error_zero_length,
                                       __func__ , "using wrong length for authenticated data" );
    return NULL;
  }
 /* проверяем наличие ключа (ресурс проверен при вызове clean) */
  if( !((hctx->key.flags)&ak_skey_flag_set_key )) {
    ak_error_message( ak_error_key_value, __func__ , "using hmac key with unassigned value" );
    return NULL;
  }

 /* обрабатываем хвост предыдущих данных */
  memset( temporary, 0, temporary_size_value );
  error = ak_error_ok;
  hctx->ctx.finalize( &hctx->ctx, data, size, temporary );
  if(( error = ak_error_get_value( )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong updating of finalized data" );
    return NULL;
  }

 /* возвращаем контекст хеширования в начальное состояние */
  if(( error = hctx->ctx.clean( &hctx->ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong cleaning of hash function context" );
    return NULL;
  }

 /* цикл по количеству 8-ми байтных блоков в ключе */
  count = hctx->key.key.size >> 3;
  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= 0x5C5C5C5C5C5C5C5CLL;
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= ((ak_uint64 *)hctx->key.mask.data)[idx];
  }
  if(( error =
         hctx->ctx.update( &hctx->ctx, hctx->key.key.data, hctx->key.key.size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "invalid 2nd step iteration for hmac key context" );
    return NULL;
  }

  for( idx = 0; idx < count; idx++ ) {
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= ((ak_uint64 *)hctx->key.mask.data)[idx];
     ((ak_uint64 *)hctx->key.key.data)[idx] ^= 0x5C5C5C5C5C5C5C5CLL;
  }
  hctx->key.remask( &hctx->key );
  hctx->key.resource.counter--; /* мы использовали ключ один раз */

 /* последний update/finalize и возврат результата */
  if( hctx->ctx.bsize == hctx->ctx.hsize ) {
    hctx->ctx.update( &hctx->ctx, temporary, hctx->ctx.hsize );
    result = hctx->ctx.finalize( &hctx->ctx, NULL, 0, out );
  } else result = hctx->ctx.finalize( &hctx->ctx, temporary, hctx->ctx.hsize, out );

 /* очищаем контекст функции хеширования, ключ не трогаем */
  hctx->ctx.clean( &hctx->ctx );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_hmac_streebog256( ak_mac mac )
{
 int error = ak_error_ok;

  /* производим первоначальную очистку контекста и устанавливаем его тип */
   memset( mac, 0, sizeof( struct mac ));
   mac->type = type_hmac;

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_streebog256( &mac->choice._hmac.ctx )) != ak_error_ok )
     return ak_error_message( error, __func__,
                                          "invalid creation of streebog256 hash function context");
  /* копируем длины */
   mac->bsize = mac->choice._hmac.ctx.bsize;
   mac->hsize = mac->choice._hmac.ctx.hsize;

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &mac->choice._hmac.key, mac->choice._hmac.ctx.bsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &mac->choice._hmac.ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* доопределяем поля секретного ключа */
   if(( mac->choice._hmac.key.oid = ak_oid_find_by_name( "hmac-streebog256" )) == NULL ) {
     error = ak_error_get_value();
     ak_hash_destroy( &mac->choice._hmac.ctx );
     ak_skey_destroy( &mac->choice._hmac.key );
     return ak_error_message( error, __func__, "wrong internal oid search");
   }

  /* устанавливаем ресурс ключа */
   mac->choice._hmac.key.resource.counter = ak_libakrypt_get_option( "hmac_key_count_resource" );
    /* _hmac.key.data не изменяется */
    /* также мы используем методы секретного ключа, установленные по-умолчанию */

  /* в заключение инициализируем методы */
   mac->clean = ak_hmac_clean;
   mac->update = ak_hmac_update;
   mac->finalize = ak_hmac_finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_hmac_streebog512( ak_mac mac )
{
 int error = ak_error_ok;

  /* производим первоначальную очистку контекста и устанавливаем его тип */
   memset( mac, 0, sizeof( struct mac ));
   mac->type = type_hmac;

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_streebog512( &mac->choice._hmac.ctx )) != ak_error_ok )
     return ak_error_message( error, __func__,
                                          "invalid creation of streebog512 hash function context");
  /* копируем длины */
   mac->bsize = mac->choice._hmac.ctx.bsize;
   mac->hsize = mac->choice._hmac.ctx.hsize;

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &mac->choice._hmac.key, mac->choice._hmac.ctx.bsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &mac->choice._hmac.ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* доопределяем поля секретного ключа */
   if(( mac->choice._hmac.key.oid = ak_oid_find_by_name( "hmac-streebog512" )) == NULL ) {
     error = ak_error_get_value();
     ak_hash_destroy( &mac->choice._hmac.ctx );
     ak_skey_destroy( &mac->choice._hmac.key );
     return ak_error_message( error, __func__, "wrong internal oid search");
   }

  /* устанавливаем ресурс ключа */
   mac->choice._hmac.key.resource.counter = ak_libakrypt_get_option( "hmac_key_count_resource" );
    /* _hmac.key.data не изменяется */
    /* также мы используем методы секретного ключа, установленные по-умолчанию */

  /* в заключение инициализируем методы */
   mac->clean = ak_hmac_clean;
   mac->update = ak_hmac_update;
   mac->finalize = ak_hmac_finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @param oid oid таблиц замен, используемых в алгоритме хеширования ГОС Р 34.11-94
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_hmac_gosthash94( ak_mac mac, ak_oid oid )
{
 int error = ak_error_ok;

  /* производим первоначальную очистку контекста и устанавливаем его тип */
   memset( mac, 0, sizeof( struct mac ));
   mac->type = type_hmac;

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_gosthash94( &mac->choice._hmac.ctx, oid )) != ak_error_ok )
     return ak_error_message( error, __func__,
                                          "invalid creation of gosthash94 hash function context");
  /* копируем длины */
   mac->bsize = mac->choice._hmac.ctx.bsize;
   mac->hsize = mac->choice._hmac.ctx.hsize;

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &mac->choice._hmac.key, mac->choice._hmac.ctx.bsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &mac->choice._hmac.ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* доопределяем поля секретного ключа */
   if(( mac->choice._hmac.key.oid = ak_oid_find_by_name( "hmac-gosthash94" )) == NULL ) {
     error = ak_error_get_value();
     ak_hash_destroy( &mac->choice._hmac.ctx );
     ak_skey_destroy( &mac->choice._hmac.key );
     return ak_error_message( error, __func__, "wrong internal oid search");
   }

  /* устанавливаем ресурс ключа */
   mac->choice._hmac.key.resource.counter = ak_libakrypt_get_option( "hmac_key_count_resource" );
    /* _hmac.key.data не изменяется */
    /* также мы используем методы секретного ключа, установленные по-умолчанию */

  /* в заключение инициализируем методы */
   mac->clean = ak_hmac_clean;
   mac->update = ak_hmac_update;
   mac->finalize = ak_hmac_finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_hmac_gosthash94_csp( ak_mac mac )
{
 return ak_mac_create_hmac_gosthash94( mac,
                                         ak_oid_find_by_name( "id-gosthash94-rfc4357-paramsetA" ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает ключевой вектор из заданного пользователем пароля и инициализационного
    вектора в соответствии с алгоритмом, описанным в отечественных рекомендациях Р 50.1.111-2016.
    При выработке используется алгоритм hmac-streebog512.

    Пароль должен представлять собой ненулевую строку символов в utf8
    кодировке. Размер вырабатываемого ключевого вектора может колебаться от 32-х до 64-х байт.

    @param pass пароль, строка символов в utf8 кодировке
    @param pass_size размер пароля в байтах, должен быть отличен от нуля.
    @param salt строка с инициализационным вектором
    @param salt_size размер инициализионного вектора в байтах
    @param c параметр, определяющий количество однотипных итераций для выработки ключа; данный
    параметр определяет время работы алгоритма
    @param dklen длина вырабатываемого ключа в байтах, величина должна принимать
    значение от 32-х до 64-х
    @param out указатель на массив, куда будет помещен результат; под данный массив должна быть
    заранее выделена память

    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hmac_pbkdf2_streebog512( const ak_pointer pass,
         const size_t pass_size, const ak_pointer salt, const size_t salt_size, const size_t c,
                                                               const size_t dklen, ak_pointer out )
{
  struct mac hctx;
  struct compress comp;
  ak_uint8 result[64];
  int error = ak_error_ok;
  size_t idx = 0, jdx = 0;

 /* в начале, многочисленные проверки входных параметров */
  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                 "using null pointer to password" );
  if( !pass_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                   "using a zero length password" );
  if( salt == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                     "using null pointer to salt" );
  if(( dklen < 32 ) || ( dklen > 64 )) return ak_error_message( ak_error_wrong_length,
                                       __func__ , "using a wrong length for resulting key vector" );
  if( out == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to resulting key vector" );
 /* создаем контекст алгоритма hmac и определяем его ключ */
  if(( error = ak_mac_create_hmac_streebog512( &hctx )) != ak_error_ok )
    return ak_error_message( error, __func__, "wrong creation of hmac-streebog512 key context" );
  if(( error = ak_mac_context_set_ptr( &hctx, pass, pass_size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong initialization of hmac secret key" );
    goto lab_exit;
  }

 /* начальная инициализация промежуточного вектора */
  memset( result, 0, 64 );
  result[3] = 1;

  if(( error = ak_compress_create_mac( &comp, &hctx )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong cretation a compress context" );
    goto lab_exit;
  }
  ak_compress_clean( &comp );
  ak_compress_update( &comp, salt, salt_size );
  ak_compress_finalize( &comp, result, 4, result );
  ak_compress_destroy( &comp );
  memcpy( out, result+64-dklen, dklen );

 /* теперь основной цикл по значению аргумента c */
  for( idx = 1; idx < c; idx++ ) {
     ak_mac_context_ptr( &hctx, result, 64, result );
     for( jdx = 0; jdx < dklen; jdx++ ) ((ak_uint8 *)out)[jdx] ^= result[64-dklen+jdx];
  }
  memset( result, 0, 64 );

  lab_exit: ak_mac_destroy( &hctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                            функции для тестирования алгоритма hmac                              */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hmac_test_streebog( void )
{
  ak_uint8 key[32] = {
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };

  ak_uint8 data[16] = {
   0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00
  };

  ak_uint8 R256[32] = {
   0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3, 0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
   0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f, 0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
  };

  ak_uint8 R512[64] = {
   0xa5, 0x9b, 0xab, 0x22, 0xec, 0xae, 0x19, 0xc6, 0x5f, 0xbd, 0xe6, 0xe5, 0xf4, 0xe9, 0xf5, 0xd8,
   0x54, 0x9d, 0x31, 0xf0, 0x37, 0xf9, 0xdf, 0x9b, 0x90, 0x55, 0x00, 0xe1, 0x71, 0x92, 0x3a, 0x77,
   0x3d, 0x5f, 0x15, 0x30, 0xf2, 0xed, 0x7e, 0x96, 0x4c, 0xb2, 0xee, 0xdc, 0x29, 0xe9, 0xad, 0x2f,
   0x3a, 0xfe, 0x93, 0xb2, 0x81, 0x4f, 0x79, 0xf5, 0x00, 0x0f, 0xfc, 0x03, 0x66, 0xc2, 0x51, 0xe6
  };

  struct mac hkey;
  char *str = NULL;
  ak_uint8 out[64];
  int error = ak_error_ok;
  ak_bool result = ak_true;
  int audit = ak_log_get_level();

 /* 1. тестируем HMAC на основе Стрибог 256 */
  if(( error = ak_mac_create_hmac_streebog256( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog256 key context" );
    return ak_false;
  }
  if(( error = ak_mac_context_set_ptr( &hkey, key, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_mac_context_ptr( &hkey, data, 16, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of hmac code" );
    result = ak_false;
    goto lab_exit;
  }
  if( !ak_ptr_is_equal( out, R256, 32 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "wrong test for hmac-streebog256 from R 50.1.113-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 32, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R256, 32, ak_false )); free( str );
    result = ak_false;
    goto lab_exit;
  }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "test for hmac-streebog256 from R 50.1.113-2016 is Ok" );
  ak_mac_destroy( &hkey );

 /* 2. тестируем HMAC на основе Стрибог 512 */
  if(( error = ak_mac_create_hmac_streebog512( &hkey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of hmac-streebog512 key context" );
    return ak_false;
  }
  if(( error = ak_mac_context_set_ptr( &hkey, key, 32 )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong assigning a constant hmac key value" );
    result = ak_false;
    goto lab_exit;
  }
  memset( out, 0, 64 );
  ak_mac_context_ptr( &hkey, data, 16, out );
  if( ak_error_get_value() != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect calculation of hmac code" );
    result = ak_false;
    goto lab_exit;
  }
  if( !ak_ptr_is_equal( out, R512, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                     "wrong test for hmac-streebog512 from R 50.1.113-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R512, 64, ak_false )); free( str );
    result = ak_false;
    goto lab_exit;
  }

  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                     "test for hmac-streebog512 from R 50.1.113-2016 is Ok" );
 lab_exit:
  ak_mac_destroy( &hkey );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hmac_test_pbkdf2( void )
{
  ak_uint8 R1[64] = {
   0x64, 0x77, 0x0a, 0xf7, 0xf7, 0x48, 0xc3, 0xb1, 0xc9, 0xac, 0x83, 0x1d, 0xbc, 0xfd, 0x85, 0xc2,
   0x61, 0x11, 0xb3, 0x0a, 0x8a, 0x65, 0x7d, 0xdc, 0x30, 0x56, 0xb8, 0x0c, 0xa7, 0x3e, 0x04, 0x0d,
   0x28, 0x54, 0xfd, 0x36, 0x81, 0x1f, 0x6d, 0x82, 0x5c, 0xc4, 0xab, 0x66, 0xec, 0x0a, 0x68, 0xa4,
   0x90, 0xa9, 0xe5, 0xcf, 0x51, 0x56, 0xb3, 0xa2, 0xb7, 0xee, 0xcd, 0xdb, 0xf9, 0xa1, 0x6b, 0x47
  };

  ak_uint8 R2[64] = {
   0x5a, 0x58, 0x5b, 0xaf, 0xdf, 0xbb, 0x6e, 0x88, 0x30, 0xd6, 0xd6, 0x8a, 0xa3, 0xb4, 0x3a, 0xc0,
   0x0d, 0x2e, 0x4a, 0xeb, 0xce, 0x01, 0xc9, 0xb3, 0x1c, 0x2c, 0xae, 0xd5, 0x6f, 0x02, 0x36, 0xd4,
   0xd3, 0x4b, 0x2b, 0x8f, 0xbd, 0x2c, 0x4e, 0x89, 0xd5, 0x4d, 0x46, 0xf5, 0x0e, 0x47, 0xd4, 0x5b,
   0xba, 0xc3, 0x01, 0x57, 0x17, 0x43, 0x11, 0x9e, 0x8d, 0x3c, 0x42, 0xba, 0x66, 0xd3, 0x48, 0xde
  };

  ak_uint8 R3[64] = {
   0xe5, 0x2d, 0xeb, 0x9a, 0x2d, 0x2a, 0xaf, 0xf4, 0xe2, 0xac, 0x9d, 0x47, 0xa4, 0x1f, 0x34, 0xc2,
   0x03, 0x76, 0x59, 0x1c, 0x67, 0x80, 0x7f, 0x04, 0x77, 0xe3, 0x25, 0x49, 0xdc, 0x34, 0x1b, 0xc7,
   0x86, 0x7c, 0x09, 0x84, 0x1b, 0x6d, 0x58, 0xe2, 0x9d, 0x03, 0x47, 0xc9, 0x96, 0x30, 0x1d, 0x55,
   0xdf, 0x0d, 0x34, 0xe4, 0x7c, 0xf6, 0x8f, 0x4e, 0x3c, 0x2c, 0xda, 0xf1, 0xd9, 0xab, 0x86, 0xc3
  };

  ak_uint8 R4[64] = {
   0x50, 0xdf, 0x06, 0x28, 0x85, 0xb6, 0x98, 0x01, 0xa3, 0xc1, 0x02, 0x48, 0xeb, 0x0a, 0x27, 0xab,
   0x6e, 0x52, 0x2f, 0xfe, 0xb2, 0x0c, 0x99, 0x1c, 0x66, 0x0f, 0x00, 0x14, 0x75, 0xd7, 0x3a, 0x4e,
   0x16, 0x7f, 0x78, 0x2c, 0x18, 0xe9, 0x7e, 0x92, 0x97, 0x6d, 0x9c, 0x1d, 0x97, 0x08, 0x31, 0xea,
   0x78, 0xcc, 0xb8, 0x79, 0xf6, 0x70, 0x68, 0xcd, 0xac, 0x19, 0x10, 0x74, 0x08, 0x44, 0xe8, 0x30
  };

  ak_uint8 password_one[8] = "password",
           password_two[9] = { 'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd' },
           salt_one[4]     = "salt",
           salt_two[5]     = { 's', 'a', 0, 'l', 't' };

  ak_uint8 out[64];
  char *str = NULL;
  int error = ak_error_ok;
  int audit = ak_log_get_level();

 /* первый тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_pbkdf2_streebog512( password_one, 8, salt_one, 4, 1, 64, out ))
                                                                                != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, R1, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 1st test for pbkdf2 from R 50.1.111-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R1, 64, ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 1st test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* второй тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_pbkdf2_streebog512( password_one, 8, salt_one, 4, 2, 64, out ))
                                                                                != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, R2, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 2nd test for pbkdf2 from R 50.1.111-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R2, 64, ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 2nd test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* третий тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_pbkdf2_streebog512( password_one, 8, salt_one, 4, 4096, 64, out ))
                                                                                != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, R3, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 3rd test for pbkdf2 from R 50.1.111-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R3, 64, ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 3rd test for pbkdf2 from R 50.1.111-2016 is Ok" );

 /* четвертый тест из Р 50.1.111-2016 */
  if(( error = ak_hmac_pbkdf2_streebog512( password_two, 9, salt_two, 5, 4096, 64, out ))
                                                                                != ak_error_ok ) {
    ak_error_message( error,__func__, "incorrect transformation password to key");
    return ak_false;
  }
  if( !ak_ptr_is_equal( out, R4, 64 )) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "wrong 4th test for pbkdf2 from R 50.1.111-2016" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, 64, ak_false )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( R4, 64, ak_false )); free( str );
    return ak_false;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
                                             "the 4th test for pbkdf2 from R 50.1.111-2016 is Ok" );

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_hmac.c  */
/* ----------------------------------------------------------------------------------------------- */
