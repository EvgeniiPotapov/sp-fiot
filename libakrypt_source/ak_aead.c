/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2018 by Axel Kenzo, axelkenzo@mail.ru                                            */
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
/*   ak_aead.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_mac.h>
 #include <ak_tools.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{64}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{64} + x^4 + x^3 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf64_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0, n = 0;
 ak_uint64 zv = 0, t = ((ak_uint64 *)y)[0], s = ((ak_uint64 *)x)[0];

 t = ((ak_uint64 *)y)[0];
 for( i = 0; i < 64; i++ ) {

   if( t&0x1 ) zv ^= s;
   t >>= 1;
   n = (s >> 63);
   s <<= 1;
   if( n ) s ^= 0x1B;
 }
 ((ak_uint64 *)z)[0] = zv;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    простейшая реализация, основанная на приведении по модулю после каждого шага алгоритма.        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf128_mul_uint64( ak_pointer z, ak_pointer x, ak_pointer y )
{
 int i = 0, n = 0;
 ak_uint64 t, s0 = ((ak_uint64 *)x)[0], s1 = ((ak_uint64 *)x)[1];

 /* обнуляем результирующее значение */
 ((ak_uint64 *)z)[0] = 0; ((ak_uint64 *)z)[1] = 0;

 /* вычисляем  произведение для младшей половины */
 t = ((ak_uint64 *)y)[0];
 for( i = 0; i < 64; i++ ) {

   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   n = s1 >> 63;
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;
   if( n ) s0 ^= 0x87;
 }

 /* вычисляем  произведение для старшей половины */
 t = ((ak_uint64 *)y)[1];
 for( i = 0; i < 63; i++ ) {

   if( t&0x1 ) { ((ak_uint64 *)z)[0] ^= s0; ((ak_uint64 *)z)[1] ^= s1; }
   t >>= 1;
   n = s1 >> 63;
   s1 <<= 1; s1 ^= ( s0 >> 63 ); s0 <<= 1;
   if( n ) s0 ^= 0x87;
 }

 if( t&0x1 ) {
   ((ak_uint64 *)z)[0] ^= s0;
   ((ak_uint64 *)z)[1] ^= s1;
 }
}


/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{64}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{64} + x^4 + x^3 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf64_mul_pcmulqdq( ak_pointer z, ak_pointer x, ak_pointer y )
{
 #ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
  const __m128i gm = _mm_set_epi64x( 0, 0x1B );
  __m128i xm = _mm_set_epi64x( 0, ((ak_uint64 *)x)[0] );
  __m128i ym = _mm_set_epi64x( 0, ((ak_uint64 *)y)[0] );

  __m128i cm = _mm_clmulepi64_si128( xm, ym, 0x00 );
  __m128i cx = _mm_set_epi64x( 0, cm[1] );

  xm = _mm_clmulepi64_si128( cx, gm, 0x00 ); xm[1] ^= cx[0];
  ym = _mm_set_epi64x( 0, xm[1] );
  xm = _mm_clmulepi64_si128( ym, gm, 0x00 );

  ((ak_uint64 *)z)[0] = cm[0]^xm[0];

 #else
  __m128i gm, xm, ym, cm, cx;

  gm.m128i_u64[0] = 0x1B; gm.m128i_u64[1] = 0;
  xm.m128i_u64[0] = ((ak_uint64 *)x)[0]; xm.m128i_u64[1] = 0;
  ym.m128i_u64[0] = ((ak_uint64 *)y)[0]; ym.m128i_u64[1] = 0;

  cm = _mm_clmulepi64_si128( xm, ym, 0x00 );
  cx.m128i_u64[0] = cm.m128i_u64[1]; cx.m128i_u64[1] = 0;

  xm = _mm_clmulepi64_si128( cx, gm, 0x00 );
  xm.m128i_u64[1] ^= cx.m128i_u64[0];
  ym.m128i_u64[0] = xm.m128i_u64[1]; ym.m128i_u64[1] = 0;
  xm = _mm_clmulepi64_si128( ym, gm, 0x00 );

  ((ak_uint64 *)z)[0] = cm.m128i_u64[0]^xm.m128i_u64[0];
 #endif
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует операцию умножения двух элементов конечного поля \f$ \mathbb F_{2^{128}}\f$,
    порожденного неприводимым многочленом
    \f$ f(x) = x^{128} + x^7 + x^2 + x + 1 \in \mathbb F_2[x]\f$. Для умножения используется
    реализация с помощью команды PCLMULQDQ.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 void ak_gf128_mul_pcmulqdq( ak_pointer z, ak_pointer a, ak_pointer b )
{
#ifdef LIBAKRYPT_HAVE_BUILTIN_SET_EPI64X
 __m128i am = _mm_set_epi64x( ((ak_uint64 *)a)[1], ((ak_uint64 *)a)[0] );
 __m128i bm = _mm_set_epi64x( ((ak_uint64 *)b)[1], ((ak_uint64 *)b)[0] );

 /* умножение */
 __m128i cm = _mm_clmulepi64_si128( am, bm, 0x00 ); // c = a0*b0
 __m128i dm = _mm_clmulepi64_si128( am, bm, 0x11 ); // d = a1*b1
 __m128i em = _mm_clmulepi64_si128( am, bm, 0x10 ); // e = a0*b1
 __m128i fm = _mm_clmulepi64_si128( am, bm, 0x01 ); // f = a1*b0

 /* приведение */
  ak_uint64 x3 = dm[1];
  ak_uint64 D = dm[0] ^ em[1] ^ fm[1] ^ (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57);

  cm[0] ^=  D ^ (D << 1) ^ (D << 2) ^ (D << 7);
  cm[1] ^=  em[0] ^ fm[0] ^ x3 ^ (x3 << 1) ^ (D >> 63) ^ (x3 << 2) ^ (D >> 62) ^ (x3 << 7) ^ (D >> 57);

  ((ak_uint64 *)z)[0] = cm[0];
  ((ak_uint64 *)z)[1] = cm[1];

#else
  __m128i am, bm, cm, dm, em, fm;
  ak_uint64 x3, D;

  am.m128i_u64[0] = ((ak_uint64 *)a)[0];  am.m128i_u64[1] = ((ak_uint64 *)a)[1];
  bm.m128i_u64[0] = ((ak_uint64 *)b)[0];  bm.m128i_u64[1] = ((ak_uint64 *)b)[1];

 /* умножение */
  cm = _mm_clmulepi64_si128( am, bm, 0x00 ); // c = a0*b0
  dm = _mm_clmulepi64_si128( am, bm, 0x11 ); // d = a1*b1
  em = _mm_clmulepi64_si128( am, bm, 0x10 ); // e = a0*b1
  fm = _mm_clmulepi64_si128( am, bm, 0x01 ); // f = a1*b0

 /* приведение */
  x3 = dm.m128i_u64[1];
  D = dm.m128i_u64[0] ^ em.m128i_u64[1] ^ fm.m128i_u64[1] ^ (x3 >> 63) ^ (x3 >> 62) ^ (x3 >> 57);

  cm.m128i_u64[0] ^=  D ^ (D << 1) ^ (D << 2) ^ (D << 7);
  cm.m128i_u64[1] ^=  em.m128i_u64[0] ^ fm.m128i_u64[0] ^ x3 ^ (x3 << 1) ^ (D >> 63) ^ (x3 << 2) ^ (D >> 62) ^ (x3 << 7) ^ (D >> 57);

  ((ak_uint64 *)z)[0] = cm.m128i_u64[0];
  ((ak_uint64 *)z)[1] = cm.m128i_u64[1];

 #endif
}
#endif

/* ----------------------------------------------------------------------------------------------- */
/*                                 реализация aead и вычисления имитовставки                       */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует значение внутренних переменных алгоритма MGM, участвующих в алгоритме
    выработки имитовставки.

    @param ctx
    @param authenticationKey
    @param iv
    @param iv_size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_authentication_clean( ak_mgm_ctx ctx,
                            ak_bckey authenticationKey, const ak_pointer iv, const size_t iv_size )
{
 ak_uint8 ivector[16]; /* временное значение синхропосылки */

 if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to internal mgm context");
 if( authenticationKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");
 if( authenticationKey->ivector.size > 16 ) return ak_error_message( ak_error_wrong_length,
                                                 __func__, "using key with very large block size" );
 /* инициализация значением и ресурс */
 if(( authenticationKey->key.flags&ak_skey_flag_set_key ) == 0 )
           return ak_error_message( ak_error_key_value, __func__,
                                               "using secret key context with undefined key value");
 if( authenticationKey->key.resource.counter <= 0 )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");

 if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
 if( iv_size != authenticationKey->ivector.size ) return ak_error_message( ak_error_wrong_length,
                                           __func__, "using initial vector with unexpected length");
 /* обнуляем необходимое */
  ctx->aflag = 0;
  ctx->abitlen = 0;
  memset( &ctx->sum, 0, 16 ); /* очищаем по максимуму */
  memset( &ctx->mulres, 0, 16 );
  memset( &ctx->h, 0, 16 );
  memset( &ctx->zcount, 0, 16 );
  memset( ivector, 0, 16 );
  memcpy( ivector, iv, iv_size ); /* копируем нужное количество байт */
 /* принудительно устанавливаем старший бит в 1 */
  // ivector[iv_size-1] = ( ivector[iv_size-1]&0x7F ) ^ 0x80;
  ivector[authenticationKey->ivector.size-1] = ( ivector[authenticationKey->ivector.size-1]&0x7F ) ^ 0x80;

 /* зашифровываем необходимое и удаляемся */
  authenticationKey->encrypt( &authenticationKey->key, ivector, &ctx->zcount );
  authenticationKey->key.resource.counter--;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
#define astep64(DATA)  authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &ctx->h ); \
                       ak_gf64_mul( &ctx->mulres, &ctx->h, (DATA) ); \
                       ctx->sum.q[0] ^= ctx->mulres.q[0]; \
                       ctx->zcount.w[1]++;

#define astep128(DATA) authenticationKey->encrypt( &authenticationKey->key, &ctx->zcount, &ctx->h ); \
                       ak_gf128_mul( &ctx->mulres, &ctx->h, (DATA) ); \
                       ctx->sum.q[0] ^= ctx->mulres.q[0]; \
                       ctx->sum.q[1] ^= ctx->mulres.q[1]; \
                       ctx->zcount.q[1]++;

/* ----------------------------------------------------------------------------------------------- */
/*! Функция обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    выработки имитовставки. Если длина входных данных не кратна длине блока алгоритма шифрования,
    то это воспринимается как конец процесса обновления (после этого вызов функции блокируется).

    @param ctx
    @param authenticationKey
    @param adata
    @param adata_size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_authentication_update( ak_mgm_ctx ctx,
                      ak_bckey authenticationKey, const ak_pointer adata, const size_t adata_size )
{
  ak_uint8 temp[16], *aptr = (ak_uint8 *)adata;
  size_t absize = authenticationKey->ivector.size;
  ak_int64 resource = 0,
           tail = (ak_int64) adata_size%absize,
           blocks = (ak_int64) adata_size/absize;

 /* проверка возможности обновления */
  if( ctx->aflag&0x1 )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                         "using this function with previously closed aead context");
 /* ни чего не задано => ни чего не обрабатываем */
  if(( adata == NULL ) || ( adata_size == 0 )) return ak_error_ok;

 /* проверка ресурса ключа */
  if( authenticationKey->key.resource.counter <= (resource = blocks + (tail > 0)))
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
  else authenticationKey->key.resource.counter -= resource;

 /* теперь основной цикл */
 if( absize == 16 ) { /* обработка 128-битным шифром */

   ctx->abitlen += ( blocks  << 7 );
   for( ; blocks > 0; blocks--, aptr += 16 ) { astep128( aptr );  }
   if( tail ) {
    memset( temp, 0, 16 );
    memcpy( temp+absize-tail, aptr, (size_t)tail );
    astep128( temp );
  /* закрываем добавление ассоциированных данных */
    ctx->aflag |= 0x1;
    ctx->abitlen += ( tail << 3 );
  }
 } else { /* обработка 64-битным шифром */

   ctx->abitlen += ( blocks << 6 );
   for( ; blocks > 0; blocks--, aptr += 8 ) { astep64( aptr ); }
   if( tail ) {
    memset( temp, 0, 8 );
    memcpy( temp+absize-tail, aptr, (size_t)tail );
    astep64( temp );
   /* закрываем добавление ассоциированных данных */
    ctx->aflag |= 0x1;
    ctx->abitlen += ( tail << 3 );
  }
 }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция завершает вычисления и возвращает значение имитовставки.

   @param ctx
   @param authenticationKey
   @param out
   @param out_size

   @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
   возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
   ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
   ak_error_get_value().                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_mgm_context_authentication_finalize( ak_mgm_ctx ctx,
                                 ak_bckey authenticationKey, ak_pointer out, const size_t out_size )
{
  ak_uint128 temp;
  ak_pointer pout = NULL;
  ak_buffer result = NULL;
  size_t absize = authenticationKey->ivector.size;

 /* проверка запрашиваемой длины iv */
  if(( out_size == 0 ) || ( out_size > absize )) {
    ak_error_message( ak_error_wrong_length, __func__, "unexpected length of integrity code" );
    return NULL;
  }
 /* проверка длины блока */
  if( absize > 16 ) {
    ak_error_message( ak_error_wrong_length, __func__, "using key with large block size" );
    return NULL;
  }

 /* традиционная проверка ресурса */
  if( authenticationKey->key.resource.counter <= 0 ) {
    ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");
    return NULL;
  } else authenticationKey->key.resource.counter--;

 /* закрываем добавление шифруемых данных */
  ctx->pflag |= 0x1;

 /* формируем последний вектор из длин */
  if(  absize&0x10 ) {
    temp.q[0] = ctx->pbitlen;
    temp.q[1] = ctx->abitlen;
    astep128( temp.b );

  } else { /* теперь тоже самое, но для 64-битного шифра */

     if(( ctx->abitlen > 0xFFFFFFFF ) || ( ctx->pbitlen > 0xFFFFFFFF )) {
       ak_error_message( ak_error_overflow, __func__, "using an algorithm with very long data" );
       return NULL;
     }
     temp.w[0] = (ak_uint32) ctx->pbitlen;
     temp.w[1] = (ak_uint32) ctx->abitlen;
     astep64( temp.b );
  }

 /* определяем указатель на область памяти, в которую будет помещен результат вычислений */
  if( out != NULL ) pout = out;
   else {
     if(( result =
              ak_buffer_new_size( authenticationKey->ivector.size )) != NULL ) pout = result->data;
      else ak_error_message( ak_error_get_value( ), __func__ , "wrong creation of result buffer" );
   }

 /* последнее шифрование и завершение работы */
  if( pout != NULL ) {
    authenticationKey->encrypt( &authenticationKey->key, &ctx->sum, &ctx->sum );
    memcpy( pout, ctx->sum.b+absize-out_size, out_size );
  } else ak_error_message( ak_error_out_of_memory, __func__ ,
                                                "incorrect memory allocation for result buffer" );
 return result;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует значение внутренних переменных алгоритма MGM, участвующих в процессе
    шифрования.

    @param ctx
    @param encryptionKey
    @param iv
    @param iv_size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_encryption_clean( ak_mgm_ctx ctx,
                            ak_bckey encryptionKey, const ak_pointer iv, const size_t iv_size )
{
 ak_uint8 ivector[16]; /* временное значение синхропосылки */

 if( ctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to internal mgm context");
 if( encryptionKey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using null pointer to authentication key");
 if( encryptionKey->ivector.size > 16 ) return ak_error_message( ak_error_wrong_length,
                                                      __func__, "using key with large block size" );
 /* инициализация значением и ресурс */
 if(( encryptionKey->key.flags&ak_skey_flag_set_key ) == 0 )
           return ak_error_message( ak_error_key_value, __func__,
                                               "using secret key context with undefined key value");
 if( encryptionKey->key.resource.counter <= 0 )
   return ak_error_message( ak_error_low_key_resource, __func__, "using key with low key resource");

 if( iv == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to initial vector");
 if( iv_size != encryptionKey->ivector.size ) return ak_error_message( ak_error_wrong_length,
                                           __func__, "using initial vector with unexpected length");
 /* обнуляем необходимое */
  ctx->pflag = 0;
  ctx->pbitlen = 0;
  memset( &ctx->ycount, 0, 16 );
  memset( &ctx->e, 0, 16 );
  memset( ivector, 0, 16 );
  memcpy( ivector, iv, iv_size ); /* копируем нужное количество байт */
 /* принудительно устанавливаем старший бит в 0 */
  ivector[iv_size-1] = ( ivector[iv_size-1]&0x7F );

 /* зашифровываем необходимое и удаляемся */
  encryptionKey->encrypt( &encryptionKey->key, ivector, &ctx->ycount );
  encryptionKey->key.resource.counter--;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
#define estep64  encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e ); \
                 outp[0] = inp[0] ^ ctx->e.q[0]; \
                 ctx->ycount.w[0]++;

#define estep128 encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e ); \
                 outp[0] = inp[0] ^ ctx->e.q[0]; \
                 outp[1] = inp[1] ^ ctx->e.q[1]; \
                 ctx->ycount.q[0]++;

/* ----------------------------------------------------------------------------------------------- */
/*! Функция зашифровывает очередной фрагмент данных и
    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    шифрования с одновременной выработкой имитовставки. Если длина входных данных не кратна длине
    блока алгоритма шифрования, то это воспринимается как конец процесса шифрования/обновления
    (после этого вызов функции блокируется).

    @param ctx
    @param encryptionKey
    @param authenticationKey
    @param in
    @param out
    @param size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_encryption_update( ak_mgm_ctx ctx, ak_bckey encryptionKey,
         ak_bckey authenticationKey, const ak_pointer in, ak_pointer out, const size_t size )
{
  int i = 0;
  ak_uint8 temp[16];
  size_t absize = encryptionKey->ivector.size;
  ak_uint64 *inp = (ak_uint64 *)in, *outp = (ak_uint64 *)out;
  ak_int64 resource = 0, tail = (ak_int64) size%absize, blocks = (ak_int64) size/absize;

 /* принудительно закрываем обновление ассоциированных данных */
  ctx->aflag |= 0x1;
 /* проверяем возможность обновления */
  if( ctx->pflag&0x1 )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                        "using this function with previously closed aead context");

 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;

 /* проверка ресурса ключа выработки имитовставки */
  if( authenticationKey != NULL ) {
    if( authenticationKey->key.resource.counter <= (resource = blocks + (tail > 0)))
      return ak_error_message( ak_error_low_key_resource, __func__,
                                                "using authentication key with low key resource");
    else authenticationKey->key.resource.counter -= resource;
  }

 /* проверка ресурса ключа шифрования */
  if( encryptionKey->key.resource.counter <= resource )
   return ak_error_message( ak_error_low_key_resource, __func__,
                                                   "using encryption key with low key resource");
  else encryptionKey->key.resource.counter -= resource;

 /* теперь обработка данных */
  ctx->pbitlen += ( absize*blocks << 3 );
  if( authenticationKey == NULL ) { /* только шифрование (без вычисления имитовставки) */

    if( absize&0x10 ) { /* режим работы для 128-битного шифра */
     /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         estep128;
      }
      /* хвост */
      if( tail ) {
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ ctx->e.b[16-tail+i];
       /* закрываем добавление шифруемых данных */
        ctx->pflag |= 0x1;
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
       /* основная часть */
        for( ; blocks > 0; blocks--, inp++, outp++ ) {
           estep64;
        }
       /* хвост */
        if( tail ) {
          encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e );
          for( i = 0; i < tail; i++ )
             ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ ctx->e.b[8-tail+i];
         /* закрываем добавление шифруемых данных */
          ctx->pflag |= 0x1;
          ctx->pbitlen += ( tail << 3 );
        }
      } /* конец шифрования без аутентификации для 64-битного шифра */

  } else { /* основной режим работы => шифрование с одновременной выработкой имитовставки */

     if( absize&0x10 ) { /* режим работы для 128-битного шифра */
      /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         estep128;
         astep128( outp );
      }
      /* хвост */
      if( tail ) {
        memset( temp, 0, 16 );
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ ctx->e.b[16-tail+i];
        memcpy( temp+16-tail, outp, (size_t)tail );
        astep128( temp );

       /* закрываем добавление шифруемых данных */
        ctx->pflag |= 0x1;
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
      /* основная часть */
       for( ; blocks > 0; blocks--, inp++, outp++ ) {
          estep64;
          astep64( outp );
       }
       /* хвост */
       if( tail ) {
         memset( temp, 0, 8 );
         encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e );
         for( i = 0; i < tail; i++ )
            ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ ctx->e.b[8-tail+i];
         memcpy( temp+8-tail, outp, (size_t)tail );
         astep64( temp );

        /* закрываем добавление шифруемых данных */
         ctx->pflag |= 0x1;
         ctx->pbitlen += ( tail << 3 );
       }
     } /* конец 64-битного шифра */
  }

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция расшифровывает очередной фрагмент данных и
    обновляет внутреннее состояние переменных алгоритма MGM, участвующих в алгоритме
    расшифрования с проверкой имитовставки. Если длина входных данных не кратна длине
    блока алгоритма шифрования, то это воспринимается как конец процесса расшифрования/обновления
    (после этого вызов функции блокируется).

    @param ctx
    @param encryptionKey
    @param authenticationKey
    @param in
    @param out
    @param size

    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). Если ранее функция была
    вызвана с данными, длина которых не кратна длине блока используемого алгоритма шифрования,
    или возникла ошибка, то возвращается код ошибки                                                */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mgm_context_decryption_update( ak_mgm_ctx ctx, ak_bckey encryptionKey,
         ak_bckey authenticationKey, const ak_pointer in, ak_pointer out, const size_t size )
{
  int i = 0;
  ak_uint8 temp[16];
  size_t absize = encryptionKey->ivector.size;
  ak_uint64 *inp = (ak_uint64 *)in, *outp = (ak_uint64 *)out;
  ak_int64 resource = 0, tail = (ak_int64) size%absize, blocks = (ak_int64) size/absize;

 /* принудительно закрываем обновление ассоциированных данных */
  ctx->aflag |= 0x1;
 /* проверяем возможность обновления */
  if( ctx->pflag&0x1 )
    return ak_error_message( ak_error_wrong_block_cipher_function, __func__ ,
                                        "using this function with previously closed aead context");

 /* ни чего не задано => ни чего не обрабатываем */
  if(( in == NULL ) || ( size == 0 )) return ak_error_ok;

 /* проверка ресурса ключа выработки имитовставки */
  if( authenticationKey != NULL ) {
    if( authenticationKey->key.resource.counter <= (resource = blocks + (tail > 0)))
      return ak_error_message( ak_error_low_key_resource, __func__,
                                                "using authentication key with low key resource");
    else authenticationKey->key.resource.counter -= resource;
  }

 /* проверка ресурса ключа шифрования */
  if( encryptionKey->key.resource.counter <= resource )
   return ak_error_message( ak_error_low_key_resource, __func__,
                                                   "using encryption key with low key resource");
  else encryptionKey->key.resource.counter -= resource;

 /* теперь обработка данных */
  ctx->pbitlen += ( absize*blocks << 3 );
  if( authenticationKey == NULL ) { /* только шифрование (без вычисления имитовставки) */
                                    /* это полная копия кода, содержащегося в функции .. _encryption_ ... */
    if( absize&0x10 ) { /* режим работы для 128-битного шифра */
     /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         estep128;
      }
      /* хвост */
      if( tail ) {
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ ctx->e.b[16-tail+i];
       /* закрываем добавление шифруемых данных */
        ctx->pflag |= 0x1;
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
       /* основная часть */
        for( ; blocks > 0; blocks--, inp++, outp++ ) {
           estep64;
        }
       /* хвост */
        if( tail ) {
          encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e );
          for( i = 0; i < tail; i++ )
             ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ ctx->e.b[8-tail+i];
         /* закрываем добавление шифруемых данных */
          ctx->pflag |= 0x1;
          ctx->pbitlen += ( tail << 3 );
        }
      } /* конец шифрования без аутентификации для 64-битного шифра */

  } else { /* основной режим работы => шифрование с одновременной выработкой имитовставки */

     if( absize&0x10 ) { /* режим работы для 128-битного шифра */
      /* основная часть */
      for( ; blocks > 0; blocks--, inp += 2, outp += 2 ) {
         astep128( inp );
         estep128;
      }
      /* хвост */
      if( tail ) {
        memset( temp, 0, 16 );
        memcpy( temp+16-tail, inp, (size_t)tail );
        astep128( temp );
        encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e );
        for( i = 0; i < tail; i++ )
           ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ ctx->e.b[16-tail+i];

       /* закрываем добавление шифруемых данных */
        ctx->pflag |= 0x1;
        ctx->pbitlen += ( tail << 3 );
      }

    } else { /* режим работы для 64-битного шифра */
      /* основная часть */
       for( ; blocks > 0; blocks--, inp++, outp++ ) {
          astep64( inp );
          estep64;
       }
       /* хвост */
       if( tail ) {
         memset( temp, 0, 8 );
         memcpy( temp+8-tail, inp, (size_t)tail );
         astep64( temp );
         encryptionKey->encrypt( &encryptionKey->key, &ctx->ycount, &ctx->e );
         for( i = 0; i < tail; i++ )
            ((ak_uint8 *)outp)[i] = ((ak_uint8 *)inp)[i] ^ ctx->e.b[8-tail+i];

        /* закрываем добавление шифруемых данных */
         ctx->pflag |= 0x1;
         ctx->pbitlen += ( tail << 3 );
       }
     } /* конец 64-битного шифра */
  }

 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует режим шифрования для блочного шифра с одновременным вычислением имитовставки.
    На вход функции подаются как данные, подлежащие зашифрованию,
    так и ассоциированные данные, которые не зашифровываются. При этом имитовставка вычисляется
    ото всех переданных на вход функции данных.

    Режим шифрования может использовать для шифрования и выработки имитовставки два различных ключа -
    в этом случае длины блоков обрабатываемых данных для ключей должны совпадать (то есть два ключа для
    алгоритмов с длиной блока 64 бита или два ключа для алгоритмов с длиной блока 128 бит).

    Если указатель на ключ шифрования равен NULL, то шифрование данных не производится и указатель на
    зашифровываемые (plain data) и зашифрованные (cipher data) данные \b должен быть равен NULL; длина
    данных (size) также \b должна принимать нулевое значение.

    Если указатель на ключ выработки имитовставки равен NULL, то аутентификация данных не производится.
    В этом случае указатель на ассоциированные данные (associated data) \b должен быть равен NULL,
    указатель на имитовставку (icode) \b должен быть равен NULL, длина дополнительных данных \b должна
    равняться нулю. В этом случае также всегда функция возвращает NULL, а код ошибки должен быть получен
    с помощью вызова функции ak_error_get_value().

    Ситуация, при которой оба указателя на ключ принимают значение NULL воспринимается как ошибка.

    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
           может принимать значение NULL;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции; может принимать значение NULL;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на зашифровываеме данные;
    @param out указатель на зашифрованные данные;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, куда будет помещено значение имитовставки;
           память должна быть выделена заранее; указатель может принимать значение NULL.
    @param icode_size ожидаемый размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;
           если значение icode_size меньше, чем длина блока, то возвращается запрашиваемое количество
           старших байт результата вычислений.

    @return Функция возвращает NULL, если указатель icode не есть NULL, в противном случае
            возвращается указатель на буффер, содержащий результат вычислений. В случае
            возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с
            помощью вызова функции ak_error_get_value().                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_bckey_context_encrypt_mgm( ak_bckey encryptionKey, ak_bckey authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
 ak_buffer result = NULL;
 int error = ak_error_ok;
 struct mgm_ctx mgm; /* контекст структуры, в которой хранятся промежуточные данные */

 /* проверки ключей */
 if(( encryptionKey == NULL ) && ( authenticationKey == NULL )) {
   ak_error_message( ak_error_null_pointer, __func__ ,
                               "using null pointers both to encryption and authentication keys" );
   return NULL;
 }
 if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
   if( encryptionKey->ivector.size != authenticationKey->ivector.size ) {
     ak_error_message( ak_error_not_equal_data, __func__, "different block sizes for given keys");
     return NULL;
   }
 }

 /* подготавливаем память */
 memset( &mgm, 0, sizeof( struct mgm_ctx ));

 /* в начале обрабатываем ассоциированные данные */
 if( authenticationKey != NULL ) {
   if(( error =
         ak_mgm_context_authentication_clean( &mgm, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator );
     return NULL;
   }
   if(( error =
         ak_mgm_context_authentication_update( &mgm, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect hashing of associated data" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator );
     return NULL;
   }
 }

 /* потом зашифровываем данные */
 if( encryptionKey != NULL ) {
   if(( error =
         ak_mgm_context_encryption_clean( &mgm, encryptionKey, iv, iv_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator );
     return NULL;
   }
   if(( error =
         ak_mgm_context_encryption_update( &mgm, encryptionKey, authenticationKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect encryption of plain data" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator );
     return NULL;
   }
 }

 /* в конце - вырабатываем имитовставку */
 if( authenticationKey != NULL ) {
   ak_error_set_value( ak_error_ok );
   result = ak_mgm_context_authentication_finalize( &mgm, authenticationKey, icode, icode_size );
   if(( error = ak_error_get_value()) != ak_error_ok ) {
     if( result != NULL ) result = ak_buffer_delete( result );
     ak_error_message( error, __func__, "incorrect finanlize of integrity code" );
   }
   ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator );
 } else /* выше проверка того, что два ключа одновременно не равну NULL =>
                                                              один из двух ключей очистит контекст */
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция реализует процедуру расшифрования с одновременной проверкой целостности зашифрованных
    данных. На вход функции подаются как данные, подлежащие расшифрованию,
    так и ассоциированные данные, которые не незашифровывавались - при этом имитовставка
    проверяется ото всех переданных на вход функции данных.


    @param encryptionKey ключ шифрования, должен быть инициализирован перед вызовом функции;
           может принимать значение NULL;
    @param authenticationKey ключ выработки кода аутентификации (имитовставки), должен быть инициализирован
           перед вызовом функции; может принимать значение NULL;

    @param adata указатель на ассоциированные (незашифровываемые) данные;
    @param adata_size длина ассоциированных данных в байтах;
    @param in указатель на расшифровываемые данные;
    @param out указатель на область памяти, куда будут помещены расшифрованные данные;
           данный указатель может совпадать с указателем in;
    @param size размер зашифровываемых данных в байтах;
    @param iv указатель на синхропосылку;
    @param iv_size длина синхропосылки в байтах;
    @param icode указатель на область памяти, в которой хранится значение имитовставки;
    @param icode_size размер имитовставки в байтах; значение не должно превышать
           размер блока шифра с помощью которого происходит шифрование и вычисляется имитовставка;

    @return Функция возвращает истину (\ref ak_true), если значение имитовтсавки совпало с
            вычисленным в ходе выполнения функции значением; если значения не совпадают,
            или в ходе выполнения функции возникла ошибка, то возвращается ложь (\ref ak_false).
            При этом код ошибки может быть получен с
            помощью вызова функции ak_error_get_value().                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_context_decrypt_mgm( ak_bckey encryptionKey, ak_bckey authenticationKey,
           const ak_pointer adata, const size_t adata_size, const ak_pointer in, ak_pointer out,
                                     const size_t size, const ak_pointer iv, const size_t iv_size,
                                                         ak_pointer icode, const size_t icode_size )
{
 struct mgm_ctx mgm; /* контекст структуры, в которой хранятся промежуточные данные */
 int error = ak_error_ok;
 ak_bool result = ak_false;

 /* проверки ключей */
 if(( encryptionKey == NULL ) && ( authenticationKey == NULL )) {
   ak_error_message( ak_error_null_pointer, __func__ ,
                               "using null pointers both to encryption and authentication keys" );
   return ak_false;
 }
 if(( encryptionKey != NULL ) && ( authenticationKey ) != NULL ) {
   if( encryptionKey->ivector.size != authenticationKey->ivector.size ) {
     ak_error_message( ak_error_not_equal_data, __func__, "different block sizes for given keys");
     return ak_false;
   }
 }

 /* подготавливаем память */
 memset( &mgm, 0, sizeof( struct mgm_ctx ));

 /* в начале обрабатываем ассоциированные данные */
 if( authenticationKey != NULL ) {
   if(( error =
         ak_mgm_context_authentication_clean( &mgm, authenticationKey, iv, iv_size ))
                                                                              != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator );
     return ak_false;
   }
   if(( error =
         ak_mgm_context_authentication_update( &mgm, authenticationKey, adata, adata_size ))
                                                                              != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect hashing of associated data" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator );
     return ak_false;
   }
 }

 /* потом расшифровываем данные */
 if( encryptionKey != NULL ) {
   if(( error =
         ak_mgm_context_encryption_clean( &mgm, encryptionKey, iv, iv_size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect initialization of internal mgm context" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator );
     return ak_false;
   }
   if(( error =
         ak_mgm_context_decryption_update( &mgm, encryptionKey, authenticationKey,
                                                             in, out, size )) != ak_error_ok ) {
     ak_error_message( error, __func__, "incorrect encryption of plain data" );
     ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator );
     return ak_false;
   }
 }

 /* в конце - вырабатываем имитовставку */
 if( authenticationKey != NULL ) {
   ak_uint8 icode2[16];
   memset( icode2, 0, 16 );

   ak_error_set_value( ak_error_ok );
   ak_mgm_context_authentication_finalize( &mgm, authenticationKey, icode2, icode_size );
   if(( error = ak_error_get_value()) != ak_error_ok )
     ak_error_message( error, __func__, "incorrect finanlize of integrity code" );
    else {
     if( !ak_ptr_is_equal( icode, icode2, icode_size ))
       ak_error_message( ak_error_not_equal_data, __func__, "wrong value of integrity code" );
      else result = ak_true;
    }
   ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &authenticationKey->key.generator );

 } else { /* выше была проверка того, что два ключа одновременно не равну NULL =>
                                                              один из двух ключей очистит контекст */
         result = ak_true; /* мы ни чего не проверяли => все хорошо */
         ak_ptr_wipe( &mgm, sizeof( struct mgm_ctx ), &encryptionKey->key.generator );
        }

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                       реализация функций для выработки чистой имитовставки                      */
/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_mgm_kuznechik( ak_mac mac )
{
 int error = ak_error_ok;

 /* производим первоначальную очистку контекста и устанавливаем его тип */
  memset( mac, 0, sizeof( struct mac ));
  mac->type = type_mgm;

 /* подготавливаем память */
  memset( &mac->choice._mgm, 0, sizeof( struct mgm_ctx ));

 /* инициализируем контекст секретного ключа */
  if(( error = ak_bckey_create_kuznechik( &mac->choice._mgm.bkey )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "wrong creation of secret block cipher key" );
  }

 /* копируем длины */
  mac->bsize = mac->hsize = mac->choice._mgm.bkey.ivector.size;

 /* доопределяем поля секретного ключа */
  if(( mac->choice._mgm.bkey.key.oid = ak_oid_find_by_name( "mgm-imito-kuznechik" )) == NULL ) {
    error = ak_error_get_value();
    ak_bckey_destroy( &mac->choice._mgm.bkey );
    return ak_error_message( error, __func__, "wrong internal oid search");
  }

 /* устанавливаем ресурс ключа */
  mac->choice._mgm.bkey.key.resource.counter = ak_libakrypt_get_option( "kuznechik_cipher_resource" );
 /* в заключение инициализируем методы */
  mac->clean = NULL; // ak_hmac_clean;
  mac->update = NULL; // ak_hmac_update;
  mac->finalize = NULL; // ak_hmac_finalize;

  //чуй

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param mac Контекст алгоритма выработки имитовставки.
    @return В случае успешного завершения функций возвращает \ref ak_error_ok. В случае
    возникновения ошибки возвращеется ее код.                                                      */
/* ----------------------------------------------------------------------------------------------- */
 int ak_mac_create_mgm_magma( ak_mac mac )
{

 return ak_error_null_pointer;
}

/* ----------------------------------------------------------------------------------------------- */
/*                             реализация функций для тестирования                                 */
/* ----------------------------------------------------------------------------------------------- */


/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование операции умножения в поле \f$ \mathbb F_{2^{64}}\f$. */
 static ak_bool ak_gf64_multiplication_test( void )
{
 int i = 0;
 char out[128];
 ak_uint64 values[8] =
  { 0x30017301ded13061LL, 0x6b1c06a3e91f0e11LL, 0x26a8f4fe69d51a14LL, 0x973a2f0c743fca03LL,
    0x895c56ed40853d3fLL, 0xae340229c65e5eceLL, 0xfe71dbde03a18ce2LL, 0x18e61c63bbbd5e52LL };

 /* сравнение с контрольными примерами */
 ak_uint64 y = 0xF000000000000011LL, x = 0x1aaabcda1115LL, z = 0, z1 = 0;
 (void)z1; /* неиспользуемая переменная */

 for( i = 0; i < 8; i++ ) {
    ak_gf64_mul_uint64( &z, &x, &y );
    if( z != values[i] ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "uint64 calculated %s on iteration %d", out, i );
      ak_ptr_to_hexstr_static( &values[i], 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "uint64 expected   %s on iteration %d", out, i );
      return ak_false;
    }
    x = y; y = z;
  }

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64

 /* сравнение с контрольными примерами */
 y = 0xF000000000000011LL, x = 0x1aaabcda1115LL, z = 0;
 for( i = 0; i < 8; i++ ) {
    ak_gf64_mul_pcmulqdq( &z, &x, &y );
    if( z != values[i] ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                           "pcmulqdq calculated %s on iteration %d", out, i );
      ak_ptr_to_hexstr_static( &values[i], 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                           "pcmulqdq expected   %s on iteration %d", out, i );
      return ak_false;
    }
    x = y; y = z;
  }

 /* проверка идентичности работы двух реализаций */
 y = 0xF1abcd5421110011LL, x = 0x1aaabcda1115LL, z = 0;
 for( i = 0; i < 1000; i++ ) {
    ak_gf64_mul_uint64( &z, &x, &y );
    ak_gf64_mul_pcmulqdq( &z1, &x, &y );
    if( z != z1 ) {
      ak_ptr_to_hexstr_static( &z, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated   %s", out );
      ak_ptr_to_hexstr_static( &z1, 8, out, 128, ak_true );
      ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
      return ak_false;
    }
    x = y; y = z;
  }
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование операции умножения в поле \f$ \mathbb F_{2^{128}}\f$. */
 static ak_bool ak_gf128_multiplication_test( void )
{
 int i = 0;
 char out[128];

 ak_uint8 a8[16] = { 0x5d, 0x47, 0x53, 0x5d, 0x72, 0x6f, 0x74, 0x63, 0x65, 0x56, 0x74, 0x73, 0x65, 0x54, 0x5b, 0x7b };
 ak_uint8 b8[16] = { 0x5d, 0x6e, 0x6f, 0x72, 0x65, 0x75, 0x47, 0x5b, 0x29, 0x79, 0x61, 0x68, 0x53, 0x28, 0x69, 0x48 };
 ak_uint8 result[16], result2[16];

 ak_uint128 a, b, m;
  a.q[0] = 0x63746f725d53475dLL; a.q[1] = 0x7b5b546573745665LL;
  b.q[0] = 0x5b477565726f6e5dLL; b.q[1] = 0x4869285368617929LL;
  m.q[0] = 0x7e4e10da323506d2LL; m.q[1] = 0x040229a09a5ed12eLL;
  memset( result, 0, 16 );
  memset( result2, 0, 16 );
 (void)i; /* неиспользуемая переменная */

 // сравниваем данные
 if( !ak_ptr_is_equal( a8, a.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant in memory representation");
   return ak_false;
 }
 if( !ak_ptr_is_equal( b8, b.q, 16 )) {
   ak_error_message( ak_error_not_equal_data, __func__, "wrong constant in memory representation");
   return ak_false;
 }

 // проверяем пример из white paper для GCM (применение pcmulqdq для GCM)
 // a = 0x7b5b54657374566563746f725d53475d
 // b = 0x48692853686179295b477565726f6e5d
 // GFMUL128 (a, b) = 0x40229a09a5ed12e7e4e10da323506d2

 ak_gf128_mul_uint64( result, &a, &b );
 if( !ak_ptr_is_equal( result, m.q, 16 )) {
   ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated %s", out );
   ak_ptr_to_hexstr_static( m.q, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 expected   %s", out );
   return ak_false;
 }

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64

 ak_gf128_mul_pcmulqdq( result2, &a, &b );
 /* сравнение с константой */
 if( !ak_ptr_is_equal( result2, m.q, 16 )) {
   ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
   ak_ptr_to_hexstr_static( m.q, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq expected   %s", out );
   return ak_false;
 }
 /* сравнение с другим способом вычисления */
 if( !ak_ptr_is_equal( result2, result, 16 )) {
   ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "pcmulqdq calculated %s", out );
   ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
   ak_error_message_fmt( ak_error_not_equal_data, __func__ , "uint64 calculated   %s", out );
   return ak_false;
 }

 /* сравнение для двух способов на нескольких значениях */
 for( i = 1; i < 1000; i++ ) {
   a.q[0] = b.q[1]; a.q[1] = b.q[0];
   memcpy( b.b, result, 16 );

   ak_gf128_mul_uint64( result, &a, &b );
   ak_gf128_mul_pcmulqdq( result2, &a, &b );
   if( !ak_ptr_is_equal( result, result2, 16 )) {
     ak_ptr_to_hexstr_static( result2, 16, out, 128, ak_true );
     ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                          "pcmulqdq calculated %s on iteration %d", out, i );
     ak_ptr_to_hexstr_static( result, 16, out, 128, ak_true );
     ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
                                            "uint64 calculated %s on iteration %d", out, i );
     return ak_false;
   }
 }
#endif
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_gfn_multiplication_test( void )
{
 int audit =  audit = ak_log_get_level();

 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing the Galois fileds arithmetic started");

#ifdef LIBAKRYPT_HAVE_BUILTIN_CLMULEPI64
 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ ,
                                       "using pcmulqdq for multiplication in finite Galois fields");
#endif

 if( ak_gf64_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^64)");
   return ak_false;
 } else
    if( audit >= ak_log_maximum )
     ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^64) is OK");

 if( ak_gf128_multiplication_test( ) != ak_true ) {
   ak_error_message( ak_error_get_value(), __func__ , "incorrect multiplication test in GF(2^128)");
   return ak_false;
 } else
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_get_value(), __func__ , "multiplication test in GF(2^128) is OK");

 if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ ,
                                         "testing the Galois fileds arithmetic ended successfully");
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_bckey_test_mgm( void )
{
  char *str = NULL;
  ak_bool result = ak_false;
  int error = ak_error_ok, audit = ak_log_get_level();

 /* константные значения ключей из ГОСТ Р 34.13-2015 */
  ak_uint8 keyAnnexA[32] = {
     0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
     0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 };

  ak_uint8 keyAnnexB[32] = {
     0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

 /* открытый текст, подлежащий зашифрованию (модификация ГОСТ Р 34.13-2015, приложение А.1) */
  ak_uint8 out[67];
  ak_uint8 plain[67] = {
     0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
     0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
     0x11, 0x00, 0x0A, 0xFF, 0xEE, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
     0xCC, 0xBB, 0xAA };

 /* несколько вариантов шифртекстов */
  ak_uint8 cipherOne[67] = {
     0xFC, 0x42, 0x9F, 0xE8, 0x3D, 0xA3, 0xB8, 0x55, 0x90, 0x6E, 0x95, 0x47, 0x81, 0x7B, 0x75, 0xA9,
     0x39, 0x6B, 0xC1, 0xAD, 0x9A, 0x06, 0xF7, 0xD3, 0x5B, 0xFD, 0xF9, 0x2B, 0x21, 0xD2, 0x75, 0x80,
     0x1C, 0x85, 0xF6, 0xA9, 0x0E, 0x5D, 0x6B, 0x93, 0x85, 0xBA, 0xA6, 0x15, 0x59, 0xB1, 0x7A, 0x49,
     0xEB, 0x6D, 0xC7, 0x95, 0x06, 0x42, 0x94, 0xAB, 0xD0, 0x83, 0xF8, 0xD3, 0xD4, 0x14, 0x0C, 0xC6,
     0x52, 0x75, 0x2C };

  ak_uint8 cipherThree[67] = {
     0x3B, 0xA0, 0x9E, 0x5F, 0x6C, 0x06, 0x95, 0xC7, 0xAE, 0x85, 0x91, 0x45, 0x42, 0x33, 0x11, 0x85,
     0x5D, 0x78, 0x2B, 0xBF, 0xD6, 0x00, 0x2E, 0x1F, 0x7D, 0x8E, 0x9C, 0xBB, 0xB8, 0x70, 0x04, 0x94,
     0x70, 0xDC, 0x7D, 0x1F, 0x73, 0xD3, 0x5D, 0x9A, 0x76, 0xA5, 0x6F, 0xCE, 0x0A, 0xCB, 0x27, 0xEC,
     0xD5, 0x75, 0xBB, 0x6A, 0x64, 0x5C, 0xF6, 0x70, 0x4E, 0xC3, 0xB5, 0xBC, 0xC3, 0x37, 0xAA, 0x47,
     0x9C, 0xBB, 0x03 };

 /* асссоциированные данные */
  ak_uint8 associated[41] = {
     0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
     0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
     0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0xEA };

 /* синхропосылки */
  ak_uint8 iv128[16] = {
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
  ak_uint8 iv64[8] = {
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92 };

 /* значения для проверки вычисленного значения */
  ak_uint8 icode[16];
  ak_uint8 icodeOne[16] = {
    0x4C, 0xDB, 0xFC, 0x29, 0x0E, 0xBB, 0xE8, 0x46, 0x5C, 0x4F, 0xC3, 0x40, 0x6F, 0x65, 0x5D, 0xCF };
  ak_uint8 icodeTwo[16] = {
    0x57, 0x4E, 0x52, 0x01, 0xA8, 0x07, 0x26, 0x60, 0x66, 0xC6, 0xE9, 0x22, 0x57, 0x6B, 0x1B, 0x89 };
  ak_uint8 icodeThree[8] = { 0x10, 0xFD, 0x10, 0xAA, 0x69, 0x80, 0x92, 0xA7 };
  ak_uint8 icodeFour[8] = { 0xC5, 0x43, 0xDE, 0xF2, 0x4C, 0xB0, 0xC3, 0xF7 };

 /* ключи для проверки */
  struct bckey kuznechikKeyA, kuznechikKeyB, magmaKeyA, magmaKeyB;

 /* инициализация ключей */
 /* - 1 - */
  if(( error = ak_bckey_create_kuznechik( &kuznechikKeyA )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of first secret key");
    return ak_false;
  }
  if(( error = ak_bckey_context_set_ptr( &kuznechikKeyA, keyAnnexA, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_destroy( &kuznechikKeyA );
    ak_error_message( error, __func__, "incorrect assigning a first constant value to Kuznechik key");
    return ak_false;
  }
 /* - 2 - */
  if(( error = ak_bckey_create_kuznechik( &kuznechikKeyB )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of second secret key");
    ak_bckey_destroy( &kuznechikKeyA );
    return ak_false;
  }
  if(( error = ak_bckey_context_set_ptr( &kuznechikKeyB, keyAnnexB, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    ak_error_message( error, __func__, "incorrect assigning a second constant value to Kuznechik key");
    return ak_false;
  }
 /* - 3 - */
  if(( error = ak_bckey_create_magma( &magmaKeyA )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of third secret key");
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    return ak_false;
  }
  if(( error = ak_bckey_context_set_ptr( &magmaKeyA, keyAnnexA, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    ak_bckey_destroy( &magmaKeyA );
    ak_error_message( error, __func__, "incorrect assigning a first constant value to Magma key");
    return ak_false;
  }
 /* - 4 - */
  if(( error = ak_bckey_create_magma( &magmaKeyB )) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect initialization of fourth secret key");
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    ak_bckey_destroy( &magmaKeyA );
    return ak_false;
  }
  if(( error = ak_bckey_context_set_ptr( &magmaKeyB, keyAnnexB, 32, ak_true )) != ak_error_ok ) {
    ak_bckey_destroy( &kuznechikKeyA );
    ak_bckey_destroy( &kuznechikKeyB );
    ak_bckey_destroy( &magmaKeyA );
    ak_bckey_destroy( &magmaKeyB );
    ak_error_message( error, __func__, "incorrect assigning a first constant value to Magma key");
    return ak_false;
  }

 /* первый тест - шифрование и имитовставка, алгоритм Кузнечик, один ключ */
  memset( icode, 0, 16 );
  ak_bckey_context_encrypt_mgm( &kuznechikKeyA, &kuznechikKeyA, associated, sizeof( associated ),
                                    plain, out, sizeof( plain ), iv128, sizeof( iv128 ), icode, 16 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for first example");
    goto exit;
  }
  if( !ak_ptr_is_equal( icode, icodeOne, sizeof( icodeOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                             "the integrity code for one Kuznechik key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( icode, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( icodeOne, 16, ak_true )); free( str );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, cipherOne, sizeof( cipherOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the encryption test for one Kuznechik key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( cipherOne, sizeof( out ), ak_true )); free( str );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if( !ak_bckey_context_decrypt_mgm( &kuznechikKeyA, &kuznechikKeyA,
            associated, sizeof( associated ), cipherOne, out, sizeof( cipherOne ),
                                                        iv128, sizeof( iv128 ), icodeOne, 16 )) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                    "checking the integrity code for one Kuznechik key is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the decryption test for one Kuznechik key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( plain, sizeof( out ), ak_true )); free( str );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
        "the 1st full encryption, decryption & integrity check test with one Kuznechik key is Ok" );

 /* второй тест - шифрование и имитовставка, алгоритм Кузнечик, два ключа */
  memset( icode, 0, 16 );
  ak_bckey_context_encrypt_mgm( &kuznechikKeyA, &kuznechikKeyB, associated, sizeof( associated ),
                                  plain, out, sizeof( plain ), iv128, sizeof( iv128 ), icode, 16 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for second example");
    goto exit;
  }
  if( !ak_ptr_is_equal( icode, icodeTwo, sizeof( icodeTwo ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                            "the integrity code for two Kuznechik keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( icode, 16, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( icodeTwo, 16, ak_true )); free( str );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, cipherOne, sizeof( cipherOne ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                           "the encryption test for two Kuznechik keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( cipherOne, sizeof( out ), ak_true )); free( str );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if( !ak_bckey_context_decrypt_mgm( &kuznechikKeyA, &kuznechikKeyB,
            associated, sizeof( associated ), cipherOne, out, sizeof( cipherOne ),
                                                        iv128, sizeof( iv128 ), icodeTwo, 16 )) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                   "checking the integrity code for two Kuznechik keys is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                           "the decryption test for two Kuznechik keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( plain, sizeof( out ), ak_true )); free( str );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
      "the 2nd full encryption, decryption & integrity check test with two Kuznechik keys is Ok" );

 /* третий тест - шифрование и имитовставка, алгоритм Магма, один ключ */
  memset( icode, 0, 16 );
  ak_bckey_context_encrypt_mgm( &magmaKeyB, &magmaKeyB, associated, sizeof( associated ),
                                    plain, out, sizeof( plain ), iv64, sizeof( iv64 ), icode, 8 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for third example");
    goto exit;
  }
  if( !ak_ptr_is_equal( icode, icodeThree, sizeof( icodeThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                 "the integrity code for one Magma key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( icode, 8, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( icodeThree, 8, ak_true )); free( str );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, cipherThree, sizeof( cipherThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the encryption test for one Magma key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( cipherThree,
                                                    sizeof( cipherThree ), ak_true )); free( str );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if( !ak_bckey_context_decrypt_mgm( &magmaKeyB, &magmaKeyB,
            associated, sizeof( associated ), cipherThree, out, sizeof( cipherThree ),
                                                          iv64, sizeof( iv64 ), icodeThree, 8 )) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                        "checking the integrity code for one Magma key is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the decryption test for one Magma key is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( plain, sizeof( plain ), ak_true )); free( str );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
           "the 3rd full encryption, decryption & integrity check test with one Magma key is Ok" );

 /* четвертый тест - шифрование и имитовставка, алгоритм Магма, два ключа */
  memset( icode, 0, 16 );
  ak_bckey_context_encrypt_mgm( &magmaKeyB, &magmaKeyA, associated, sizeof( associated ),
                                    plain, out, sizeof( plain ), iv64, sizeof( iv64 ), icode, 8 );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect encryption for fourth example");
    goto exit;
  }
  if( !ak_ptr_is_equal( icode, icodeFour, sizeof( icodeFour ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                                "the integrity code for two Magma keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( icode, 8, ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( icodeFour, 8, ak_true )); free( str );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, cipherThree, sizeof( cipherThree ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                              "the encryption test for two Magma keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( cipherThree,
                                                    sizeof( cipherThree ), ak_true )); free( str );
    goto exit;
  }

  memset( out, 0, sizeof( out ));
  if( !ak_bckey_context_decrypt_mgm( &magmaKeyB, &magmaKeyA,
            associated, sizeof( associated ), cipherThree, out, sizeof( cipherThree ),
                                                          iv64, sizeof( iv64 ), icodeFour, 8 )) {
    ak_error_message( ak_error_get_value(), __func__ ,
                                       "checking the integrity code for two Magma keys is wrong" );
    goto exit;
  }
  if( !ak_ptr_is_equal( out, plain, sizeof( plain ))) {
    ak_error_message( ak_error_not_equal_data, __func__ ,
                                              "the decryption test for two Magma keys is wrong" );
    ak_log_set_message( str = ak_ptr_to_hexstr( out, sizeof( out ), ak_true )); free( str );
    ak_log_set_message( str = ak_ptr_to_hexstr( plain, sizeof( plain ), ak_true )); free( str );
    goto exit;
  }
  if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
        "the 4th full encryption, decryption & integrity check test with two Magma keys is Ok" );

 /* только здесь все хорошо */
  result = ak_true;

 /* освобождение памяти */
  exit:
  ak_bckey_destroy( &magmaKeyB );
  ak_bckey_destroy( &magmaKeyA );
  ak_bckey_destroy( &kuznechikKeyB );
  ak_bckey_destroy( &kuznechikKeyA );

 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_aead.c  */
/* ----------------------------------------------------------------------------------------------- */
