/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                    */
/*   All rights reserved.                                                                          */
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
/*   ak_streebog.c                                                                                 */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_parameters.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура для хранения внутренних данных контекста функции хеширования Стрибог          */
 struct streebog {
 /*! \brief вектор h - временный */
  ak_uint64 H[8];
 /*! \brief вектор n - временный */
  ak_uint64 N[8];
 /*! \brief вектор  \f$ \Sigma \f$ - контрольная сумма */
  ak_uint64 SIGMA[8];
};

/* ----------------------------------------------------------------------------------------------- */
/*! Преобразование LPS (\b важно: мы предполагаем, что данные содержат 64 байта)                   */
 static inline void streebog_lps( ak_uint64 *result, const ak_uint64 *data )
{
  int idx = 0, idx2 = 0;
  unsigned char *a = (unsigned char *)data; /* приводим к массиву байт */

  /* Все три преобразования вместе                           */
  /* (этот очень короткий код был предложен Павлом Лебедевым */
  for( idx = 0; idx < 8; idx++ ) {
    ak_uint64 sidx = idx, c = 0;
    for( idx2 = 0; idx2 < 8; idx2++, sidx += 8 )
      c ^= streebog_Areverse_expand[idx2][gost_pi[a[sidx]]];
    result[idx] = c;
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Преобразование X (\b важно: мы предполагаем, что оба массива содержат по 64 байта)             */
 static inline void streebog_x( ak_uint64 *r, const ak_uint64 *k, const ak_uint64 *a )
{
  int idx = 0;
  for( idx = 0; idx < 8; idx++ ) r[idx] = k[idx] ^ a[idx];
}

/* ----------------------------------------------------------------------------------------------- */
/*! Преобразование G (\b важно: мы предполагаем, что данные содержат 64 байта)                     */
 static inline void streebog_g( struct streebog *ctx, ak_uint64 *n, const ak_uint64 *m )
{
   int idx = 0;
   ak_uint64 K[8], T[8], B[8];
       if( n != NULL ) {
         streebog_x( B, ctx->H, n );
         streebog_lps( K, B );
       }
        else
         streebog_lps( K, ctx->H );
       /* K - ключ K1 */
       for( idx = 0; idx < 8; idx++ ) T[idx] = m[idx]; /* memcpy( T, m, 64 ); */
       for( idx = 0; idx < 12; idx++ ) {
          streebog_x( B, T, K ); streebog_lps( T, B ); /* преобразуем текст */
          streebog_x( B, K, streebog_c[idx] ); streebog_lps( K, B );   /* новый ключ */
       }
       /* изменяем значение переменной h */
       for ( idx = 0; idx < 8; idx++ ) ctx->H[idx] ^= T[idx] ^ K[idx] ^ m[idx];
}

/* ----------------------------------------------------------------------------------------------- */
/*! Преобразование Add (увеличения счетчика длины обработаного сообщения)                          */
 static inline void streebog_add( struct streebog *ctx, ak_uint64 size )
{
   ak_uint64 tmp = size + ctx->N[0];
   if( tmp < ctx->N[0] ) ctx->N[1]++;
   ctx->N[0] = tmp;  /* такой код позволяет обработать сообщения, длиной не более 2^125 байт */
}

/* ----------------------------------------------------------------------------------------------- */
/*! Преобразование SAdd (Прибавление к массиву S вектора по модулю \f$ 2^{512} \f$)                */
 static inline void streebog_sadd( struct streebog *ctx,  const ak_uint64 *data )
{
   int i = 0;
   ak_uint64 carry = 0;
   for( i = 0; i < 8; i++ )
   {
      if( carry ) {
                    ctx->SIGMA[i] ++;
                    if( ctx->SIGMA[i] ) carry = 0;
      }
      ctx->SIGMA[i] += data[i];
      if( ctx->SIGMA[i] < data[i] ) carry = 1;
   }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очистки контекста.
    @param ctx указатель на контекст структуры struct hash                                         */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_hash_streebog_clean( ak_pointer ctx )
{
  struct streebog *sx = NULL;
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer,
                                                    __func__ , "using null pointer to a context" );

  sx = ( struct streebog * ) (( ak_hash ) ctx )->data;
  memset( sx->N, 0, 64 );
  memset( sx->SIGMA, 0, 64 );
  if( (( ak_hash ) ctx )->hsize == 32 ) memset( sx->H, 1, 64 );
     else memset( sx->H, 0, 64 );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Основное циклическое преобразование (Этап 2)                                                   */
 static int ak_hash_streebog_update( ak_pointer ctx, const ak_pointer in, const size_t size )
{
  ak_uint64 quot = 0, *dt = NULL;
  struct streebog *sx = NULL;

  if( ctx == NULL ) return  ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using null pointer to a context" );
  if( !size ) return ak_error_message( ak_error_zero_length,
                                                 __func__ , "using zero length for hash data" );
  quot = size/(( ak_hash ) ctx )->bsize;
  if( size - quot*(( ak_hash ) ctx )->bsize ) /* длина данных должна быть кратна ctx->bsize */
    return ak_error_message( ak_error_wrong_length, __func__ , "using data with wrong length" );

  dt = ( ak_uint64 *) in;
  sx = ( struct streebog * ) (( ak_hash ) ctx )->data;
  do{
      streebog_g( sx, sx->N, dt );
      streebog_add( sx, 512 );
      streebog_sadd( sx, dt );
      quot--; dt += 8;
  } while( quot > 0 );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static ak_buffer ak_hash_streebog_finalize( ak_pointer ctx, const ak_pointer in,
                                                                 const size_t size, ak_pointer out )
{
  ak_uint64 m[8];
  ak_pointer pout = NULL;
  ak_buffer result = NULL;
  unsigned char *mhide = NULL;
  struct streebog sx; /* структура для хранения копии текущего состояния контекста */

  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to a context" );
    return NULL;
  }
  if( size >= 64 ) {
    ak_error_message( ak_error_zero_length, __func__ ,
                                             "using wrong length for finalized hash data" );
    return NULL;
  }

  /* формируем временный текст */
  memset( m, 0, 64 );
  if( in != NULL )
    memcpy( m, in, ( ak_uint32 )size ); // здесь приведение типов корректно, поскольку 0 <= size < 64
  mhide = ( unsigned char * )m;
  mhide[size] = 1; /* дополнение */

  /* при финализации мы изменяем копию существующей структуры */
  memcpy( &sx, ( struct streebog * ) (( ak_hash ) ctx )->data, sizeof( struct streebog ));
  streebog_g( &sx, sx.N, m );
  streebog_add( &sx, size << 3 );
  streebog_sadd( &sx, m );
  streebog_g( &sx, NULL, sx.N );
  streebog_g( &sx, NULL, sx.SIGMA );

 /* определяем указатель на область памяти, в которую будет помещен результат вычислений */
  if( out != NULL ) pout = out;
   else {
     if(( result = ak_buffer_new_size((( ak_hash )ctx)->hsize )) != NULL ) pout = result->data;
      else ak_error_message( ak_error_get_value( ), __func__ ,
                                                  "wrong creation of result buffer" );
   }

 /* копируем нужную часть результирующего массива или выдаем сообщение об ошибке */
  if( pout != NULL ) {
    if((( ak_hash )ctx)->hsize == 64 ) memcpy( pout, sx.H, 64 );
      else memcpy( pout, sx.H+4, 32 );
  } else ak_error_message( ak_error_out_of_memory, __func__ ,
                                                  "incorrect memory allocation for result buffer" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    ГОСТ Р 34.11-2012, с длиной хэшкода, равной 256 бит (функция Стрибог256).

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_create_streebog256( ak_hash ctx )
{
  int error = ak_error_ok;

 /* выполняем проверку */
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to hash context" );
 /* инициализируем контекст */
  if(( error = ak_hash_create( ctx, sizeof( struct streebog ), 64 )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect streebog context creation" );

 /* устанавливаем размер хешхода и OID алгоритма хеширования */
  ctx->hsize = 32; /* длина хешкода составляет 256 бит */
  if(( ctx->oid = ak_oid_find_by_name( "streebog256" )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

 /* устанавливаем функции - обработчики событий */
  ctx->clean =     ak_hash_streebog_clean;
  ctx->update =    ak_hash_streebog_update;
  ctx->finalize =  ak_hash_streebog_finalize;

 /* инициализируем память */
  ak_hash_streebog_clean( ctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст алгоритма бесключевого хеширования, регламентируемого стандартом
    ГОСТ Р 34.11-2012, с длиной хэшкода, равной 512 бит (функция Стрибог512).

    @param ctx контекст функции хеширования
    @return Функция возвращает код ошибки или \ref ak_error_ok (в случае успеха)                   */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hash_create_streebog512( ak_hash ctx )
{
  int error = ak_error_ok;

 /* выполняем проверку */
  if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                     "using null pointer to hash context" );
 /* инициализируем контекст */
  if(( error = ak_hash_create( ctx, sizeof( struct streebog ), 64 )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect streebog context creation" );

 /* устанавливаем размер хешхода и OID алгоритма хеширования */
  ctx->hsize = 64; /* длина хешкода составляет 512 бит */
  if(( ctx->oid = ak_oid_find_by_name( "streebog512" )) == NULL )
      return ak_error_message( ak_error_get_value(), __func__, "internal OID search error");

 /* устанавливаем функции - обработчики событий */
  ctx->clean =     ak_hash_streebog_clean;
  ctx->update =    ak_hash_streebog_update;
  ctx->finalize =  ak_hash_streebog_finalize;

 /* инициализируем память */
  ak_hash_streebog_clean( ctx );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! первое тестовое сообщение (см. текст стандарта ГОСТ Р 34.11-2012, прил. А, пример 1) */
 static ak_uint8 streebog_M1_message[63] = {
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
   0x30, 0x31, 0x32 };

/*! второе тестовое сообщение (см. текст стандарта ГОСТ Р 34.11-2012, прил. А, пример 2) */
 static ak_uint8 streebog_M2_message[72] = {
   0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8, 0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8,
   0xe1, 0xee, 0xe6, 0xe8, 0x20, 0xe2, 0xed, 0xf3, 0xf6, 0xe8, 0x2c, 0x20, 0xe2, 0xe5,
   0xfe, 0xf2, 0xfa, 0x20, 0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1, 0xf2, 0xf0,
   0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20, 0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0,
   0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb, 0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5,
   0xe2, 0xfb };

 static ak_uint8 streebog256_testM1[32] = {
   0x9D, 0x15, 0x1E, 0xEF, 0xD8, 0x59, 0x0B, 0x89, 0xDA, 0xA6, 0xBA, 0x6C, 0xB7, 0x4A, 0xF9, 0x27,
   0x5D, 0xD0, 0x51, 0x02, 0x6B, 0xB1, 0x49, 0xA4, 0x52, 0xFD, 0x84, 0xE5, 0xE5, 0x7B, 0x55, 0x00
 };

 static ak_uint8 streebog256_testM2[32] = {
   0x9D, 0xD2, 0xFE, 0x4E, 0x90, 0x40, 0x9E, 0x5D, 0xA8, 0x7F, 0x53, 0x97, 0x6D, 0x74, 0x05, 0xB0,
   0xC0, 0xCA, 0xC6, 0x28, 0xFC, 0x66, 0x9A, 0x74, 0x1D, 0x50, 0x06, 0x3C, 0x55, 0x7E, 0x8F, 0x50
 };

 static ak_uint8 streebog256_testM3[32] = {
   0x3E, 0x7D, 0xEA, 0x7F, 0x23, 0x84, 0xB6, 0xC5, 0xA3, 0xD0, 0xE2, 0x4A, 0xAA, 0x29, 0xC0, 0x5E,
   0x89, 0xDD, 0xD7, 0x62, 0x14, 0x50, 0x30, 0xEC, 0x22, 0xC7, 0x1A, 0x6D, 0xB8, 0xB2, 0xC1, 0xF4
 };

 static ak_uint8 streebog256_testM4[32] = {
   0x36, 0x81, 0x6A, 0x82, 0x4D, 0xCB, 0xE7, 0xD6, 0x17, 0x1A, 0xA5, 0x85, 0x00, 0x74, 0x1F, 0x2E,
   0xA2, 0x75, 0x7A, 0xE2, 0xE1, 0x78, 0x4A, 0xB7, 0x2C, 0x5C, 0x3C, 0x6C, 0x19, 0x8D, 0x71, 0xDA
 };

 static ak_uint8 streebog256_testM5[32] = {
   0x3F, 0x53, 0x9A, 0x21, 0x3E, 0x97, 0xC8, 0x02, 0xCC, 0x22, 0x9D, 0x47, 0x4C, 0x6A, 0xA3, 0x2A,
   0x82, 0x5A, 0x36, 0x0B, 0x2A, 0x93, 0x3A, 0x94, 0x9F, 0xD9, 0x25, 0x20, 0x8D, 0x9C, 0xE1, 0xBB
 };

 static ak_uint8 streebog512_testM1[64] = {
   0x1B, 0x54, 0xD0, 0x1A, 0x4A, 0xF5, 0xB9, 0xD5, 0xCC, 0x3D, 0x86, 0xD6, 0x8D, 0x28, 0x54, 0x62,
   0xB1, 0x9A, 0xBC, 0x24, 0x75, 0x22, 0x2F, 0x35, 0xC0, 0x85, 0x12, 0x2B, 0xE4, 0xBA, 0x1F, 0xFA,
   0x00, 0xAD, 0x30, 0xF8, 0x76, 0x7B, 0x3A, 0x82, 0x38, 0x4C, 0x65, 0x74, 0xF0, 0x24, 0xC3, 0x11,
   0xE2, 0xA4, 0x81, 0x33, 0x2B, 0x08, 0xEF, 0x7F, 0x41, 0x79, 0x78, 0x91, 0xC1, 0x64, 0x6F, 0x48
 };

 static ak_uint8 streebog512_testM2[64] = {
   0x1E, 0x88, 0xE6, 0x22, 0x26, 0xBF, 0xCA, 0x6F, 0x99, 0x94, 0xF1, 0xF2, 0xD5, 0x15, 0x69, 0xE0,
   0xDA, 0xF8, 0x47, 0x5A, 0x3B, 0x0F, 0xE6, 0x1A, 0x53, 0x00, 0xEE, 0xE4, 0x6D, 0x96, 0x13, 0x76,
   0x03, 0x5F, 0xE8, 0x35, 0x49, 0xAD, 0xA2, 0xB8, 0x62, 0x0F, 0xCD, 0x7C, 0x49, 0x6C, 0xE5, 0xB3,
   0x3F, 0x0C, 0xB9, 0xDD, 0xDC, 0x2B, 0x64, 0x60, 0x14, 0x3B, 0x03, 0xDA, 0xBA, 0xC9, 0xFB, 0x28
 };

 static ak_uint8 streebog512_testM3[64] = {
   0x8E, 0x94, 0x5D, 0xA2, 0x09, 0xAA, 0x86, 0x9F, 0x04, 0x55, 0x92, 0x85, 0x29, 0xBC, 0xAE, 0x46,
   0x79, 0xE9, 0x87, 0x3A, 0xB7, 0x07, 0xB5, 0x53, 0x15, 0xF5, 0x6C, 0xEB, 0x98, 0xBE, 0xF0, 0xA7,
   0x36, 0x2F, 0x71, 0x55, 0x28, 0x35, 0x6E, 0xE8, 0x3C, 0xDA, 0x5F, 0x2A, 0xAC, 0x4C, 0x6A, 0xD2,
   0xBA, 0x3A, 0x71, 0x5C, 0x1B, 0xCD, 0x81, 0xCB, 0x8E, 0x9F, 0x90, 0xBF, 0x4C, 0x1C, 0x1A, 0x8A
 };

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hash_test_streebog256( void )
{
  struct hash ctx; /* контекст функции хеширования */
  ak_uint8 out[32]; /* буффер длиной 32 байта (256 бит) для получения результата */
  char *str = NULL;
  int error = ak_error_ok;
  ak_bool result = ak_true;
  int audit = ak_log_get_level();

 /* инициализируем контекст функции хешиирования */
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of streenbog256 context" );
    return ak_false;
  }

 /* первый пример из приложения А (ГОСТ Р 34.11-2012) */
  ak_hash_context_ptr( &ctx, streebog_M1_message, 63, out );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if( ak_ptr_is_equal( streebog256_testM1, out, 32 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the 1st test from GOST R 34.11-2012 is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the 1st test from GOST R 34.11-2012 is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr( streebog256_testM1, 32, ak_false ))); free( str );
      result = ak_false;
      goto lab_exit;
    }

 /* второй пример из приложения А (ГОСТ Р 34.11-2012) */
  ak_hash_context_ptr( &ctx, streebog_M2_message, 72, out );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if( ak_ptr_is_equal( streebog256_testM2, out, 32 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the 2nd test from GOST R 34.11-2012 is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the 2nd test from GOST R 34.11-2012 is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr( streebog256_testM2, 32, ak_false ))); free( str );
      result = ak_false;
      goto lab_exit;
    }

 /* первый пример из Википедии */
  ak_hash_context_ptr( &ctx, "The quick brown fox jumps over the lazy dog", 43, out );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if( ak_ptr_is_equal( streebog256_testM3, out, 32 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the \"lazy dog\" test from Wikipedia is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the \"lazy dog\" test from Wikipedia is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr( streebog256_testM3, 32, ak_false ))); free( str );
      result = ak_false;
      goto lab_exit;
    }

 /* второй пример из Википедии */
  ak_hash_context_ptr( &ctx, "The quick brown fox jumps over the lazy dog.", 44, out );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if( ak_ptr_is_equal( streebog256_testM4, out, 32 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
                                           "the \"lazy dog with point\" test from Wikipedia is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
                                        "the \"lazy dog with point\" test from Wikipedia is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr( streebog256_testM4, 32, ak_false ))); free( str );
      result = ak_false;
      goto lab_exit;
    }

 /* хеширование пустого вектора */
  ak_hash_context_ptr( &ctx, "", 0, out );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog256 code" );
    result = ak_false;
    goto lab_exit;
  }

  if( ak_ptr_is_equal( streebog256_testM5, out, 32 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( out, 32, ak_false ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr( streebog256_testM5, 32, ak_false ))); free( str );
      result = ak_false;
      goto lab_exit;
    }

 /* уничтожаем контекст */
  lab_exit: ak_hash_destroy( &ctx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*!  @return Если тестирование прошло успешно возвращается ak_true (истина). В противном случае,
     возвращается ak_false.                                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_hash_test_streebog512( void )
{
  struct hash ctx; /* контекст функции хеширования */
  ak_uint8 out[64]; /* буффер длиной 64 байта (512 бит) для получения результата */
  char *str = NULL;
  int error = ak_error_ok;
  ak_bool result = ak_true;
  int audit = ak_log_get_level();

 /* инициализируем контекст функции хешиирования */
  if(( error = ak_hash_create_streebog512( &ctx )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong initialization of streenbog512 context" );
    return ak_false;
  }

 /* первый пример из приложения А (ГОСТ Р 34.11-2012) */
  ak_hash_context_ptr( &ctx, streebog_M1_message, 63, out );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog512 code" );
    result = ak_false;
    goto lab_exit;
  }

  if( ak_ptr_is_equal( streebog512_testM1, out, 64 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the 1st test from GOST R 34.11-2012 is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the 1st test from GOST R 34.11-2012 is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( out, 64, ak_false ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr( streebog512_testM1, 64, ak_false ))); free( str );
      result = ak_false;
      goto lab_exit;
    }

 /* второй пример из приложения А (ГОСТ Р 34.11-2012) */
  ak_hash_context_ptr( &ctx, streebog_M2_message, 72, out );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog512 code" );
    result = ak_false;
    goto lab_exit;
  }

  if( ak_ptr_is_equal( streebog512_testM2, out, 64 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the 2nd test from GOST R 34.11-2012 is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the 2nd test from GOST R 34.11-2012 is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( out, 64, ak_false ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr( streebog512_testM2, 64, ak_false ))); free( str );
      result = ak_false;
      goto lab_exit;
    }

 /* хеширование пустого вектора */
  ak_hash_context_ptr( &ctx, "", 0, out );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid calculation of streebog512 code" );
    result = ak_false;
    goto lab_exit;
  }

  if( ak_ptr_is_equal( streebog512_testM3, out, 64 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ , "the zero length vector test is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ , "the zero length vector test is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( out, 64, ak_false ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr( streebog512_testM3, 64, ak_false ))); free( str );
      result = ak_false;
      goto lab_exit;
    }

 /* уничтожаем контекст */
  lab_exit: ak_hash_destroy( &ctx );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                  ak_streebog.c  */
/* ----------------------------------------------------------------------------------------------- */
