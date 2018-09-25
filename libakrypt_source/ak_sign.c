/* ----------------------------------------------------------------------------------------------- */
/*   Copyright (c) 2008 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                    */
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
/*   ak_sign.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_sign.h>
 #include <ak_parameters.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает случайный вычет \f$ m \f$ из кольца вычетов \f$ \mathbb Z_q\f$
    и заменяет значение ключа \f$ k \f$ на величину \f$ km^{-1} \pmod{q} \f$.
    Величина \f$ q \f$ должна быть простым числом, помещенным в параметры эллиптической кривой,
    на которые указывает `skey->data`.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_signkey_set_mask_multiplicative( ak_skey skey )
{
  ak_mpznmax u;
  ak_wcurve wc = NULL;
  int error = ak_error_ok;


 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

  if(( wc = ( ak_wcurve ) skey->data ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                      "using internal null pointer to elliptic curve" );
 /* создаем маску*/
  if(( error = skey->generator.random( &skey->generator,
                                           skey->mask.data, skey->mask.size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

 /* накладываем маску на ключ
    - для этого мы вычисляем значение маски M^{-1} mod(q), хранящееся в skey->mask,
      и присваиваем ключу K значение KM mod(q)
    - при этом значения ключа и маски хранятся в представлении Монтгомери    */

 /* приводим случайное число по модулю q и сразу считаем, что это число в представлении Монтгомери */
  ak_mpzn_rem( (ak_uint64 *)skey->mask.data, (ak_uint64 *)skey->mask.data, wc->q, wc->size );

 /* приводим значение ключа по модулю q, а потом переводим в представление Монтгомери */
  ak_mpzn_rem( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data, wc->q, wc->size );
  ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data, wc->r2q,
                                                                           wc->q, wc->nq, wc->size);
  ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data,
                (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->mask.data, wc->q, wc->nq, wc->size);

 /* вычисляем обратное значение для маски */
  ak_mpzn_set_ui( u, wc->size, 2 );
  ak_mpzn_sub( u, wc->q, u, wc->size );
  ak_mpzn_modpow_montgomery( (ak_uint64 *)skey->mask.data, // m <- m^{q-2} (mod q)
                                         (ak_uint64 *)skey->mask.data, u, wc->q, wc->nq, wc->size );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает случайный вычет \f$ \zeta \f$ из кольца вычетов \f$ \mathbb Z_q\f$
    и заменяет значение ключа \f$ k \f$ и значение маски \f$ m \f$  на значения
    \f$ k \equiv k\zeta \pmod{q} \f$ и \f$  m \equiv m\zeta^{-1} \pmod{q} \f$.

    Величина \f$ q \f$ должна быть простым числом, помещенным в параметры эллиптической кривой,
    на которые указывает `skey->data`.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 static int ak_signkey_remask_multiplicative( ak_skey skey )
{
  ak_mpznmax u, zeta;
  ak_wcurve wc = NULL;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

  if(( wc = ( ak_wcurve ) skey->data ) == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                      "using internal null pointer to elliptic curve" );
 /* создаем маску */
  if(( error = skey->generator.random( &skey->generator, zeta, skey->mask.size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

 /* приводим случайное число по модулю q и сразу считаем, что это число в представлении Монтгомери */
  ak_mpzn_rem( zeta, zeta, wc->q, wc->size );

 /* домножаем ключ на случайное число */
  ak_mpzn_mul_montgomery( (ak_uint64 *)skey->key.data, (ak_uint64 *)skey->key.data,
                                                                    zeta, wc->q, wc->nq, wc->size );
 /* вычисляем обратное значение zeta */
  ak_mpzn_set_ui( u, wc->size, 2 );
  ak_mpzn_sub( u, wc->q, u, wc->size );
  ak_mpzn_modpow_montgomery( zeta, zeta, u, wc->q, wc->nq, wc->size ); // z <- z^{q-2} (mod q)

 /* домножаем маску на обратное значение zeta */
  ak_mpzn_mul_montgomery( (ak_uint64 *)skey->mask.data, (ak_uint64 *)skey->mask.data,
                                                                   zeta, wc->q, wc->nq, wc->size );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 static int ak_signkey_set_icode_multiplicative( ak_skey skey )
{
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_signkey_check_icode_multiplicative( ak_skey skey )
{
 return ak_error_ok;
}


/* ----------------------------------------------------------------------------------------------- */
/*                    функции для работы с секретными ключами электронной подписи                  */
/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа
    @param wc контекст параметров эллиптической кривой
    @return Функция возвращает ноль (\ref ak_error_ok) в случае успешной иниициализации контекста.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_create_streebog256( ak_signkey sctx, ak_wcurve wc )
{
 int error = ak_error_ok;

   if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
   if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using null pointer to elliptic curve context" );
   if( wc->size != ak_mpzn256_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                       "elliptic curve defined over wrong field" );
  /* первичная инициализация */
   memset( sctx, 0, sizeof( struct signkey ));

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_streebog256( &sctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &sctx->key, sctx->ctx.hsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &sctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* устанавливаем OID алгоритма */
   if(( sctx->key.oid = ak_oid_find_by_name( "sign256" )) == NULL )
     ak_error_message( ak_error_get_value(), __func__ ,
                                                     "incorrect initialization of algorithm " );
  /* устанавливаем эллиптическую кривую */
   sctx->key.data = wc;

  /* При удалении ключа не нужно освобождать память из под параметров эллиптической кривой  */
   sctx->key.flags |= ak_skey_flag_data_nonfree;

 /* в заключение определяем указатели на методы */
  sctx->key.set_mask = ak_signkey_set_mask_multiplicative;
  sctx->key.remask = ak_signkey_remask_multiplicative;
  sctx->key.set_icode = ak_signkey_set_icode_multiplicative;
  sctx->key.check_icode = ak_signkey_check_icode_multiplicative;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа
    @param wc контекст параметров эллиптической кривой
    @return Функция возвращает ноль (\ref ak_error_ok) в случае успешной иниициализации контекста.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_create_streebog512( ak_signkey sctx, ak_wcurve wc )
{
 int error = ak_error_ok;

   if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
   if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using null pointer to elliptic curve context" );
   if( wc->size != ak_mpzn512_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                       "elliptic curve defined over wrong field" );
  /* первичная инициализация */
   memset( sctx, 0, sizeof( struct signkey ));

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_streebog512( &sctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &sctx->key, sctx->ctx.hsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &sctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* устанавливаем OID алгоритма */
   if(( sctx->key.oid = ak_oid_find_by_name( "sign512" )) == NULL )
     ak_error_message( ak_error_get_value(), __func__ ,
                                                     "incorrect initialization of algorithm " );
  /* устанавливаем эллиптическую кривую */
   sctx->key.data = wc;

  /* При удалении ключа не нужно освобождать память из под параметров эллиптической кривой  */
   sctx->key.flags |= ak_skey_flag_data_nonfree;

 /* в заключение определяем указатели на методы */
  sctx->key.set_mask = ak_signkey_set_mask_multiplicative;
  sctx->key.remask = ak_signkey_remask_multiplicative;
  sctx->key.set_icode = ak_signkey_set_icode_multiplicative;
  sctx->key.check_icode = ak_signkey_check_icode_multiplicative;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа
    @param wc контекст параметров эллиптической кривой
    @return Функция возвращает ноль (\ref ak_error_ok) в случае успешной иниициализации контекста.
    В случае возникновения ошибки возвращается ее код.                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_create_ak_signkey_create_gosthash94( ak_signkey sctx, ak_wcurve wc )
{
 int error = ak_error_ok;

   if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                    "using null pointer to digital signature secret key context" );
   if( wc == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using null pointer to elliptic curve context" );
   if( wc->size != ak_mpzn256_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                       "elliptic curve defined over wrong field" );
  /* первичная инициализация */
   memset( sctx, 0, sizeof( struct signkey ));

  /* инициализируем контекст функции хеширования */
   if(( error = ak_hash_create_gosthash94_csp( &sctx->ctx )) != ak_error_ok )
     return ak_error_message( error, __func__, "invalid creation of hash function context");

  /* инициализируем контекст секретного ключа */
   if(( error = ak_skey_create( &sctx->key, sctx->ctx.hsize, 8 )) != ak_error_ok ) {
     ak_hash_destroy( &sctx->ctx );
     return ak_error_message( error, __func__, "wrong creation of secret key" );
   }

  /* устанавливаем OID алгоритма */
   if(( sctx->key.oid = ak_oid_find_by_name( "sign256-gosthash94" )) == NULL )
     ak_error_message( ak_error_get_value(), __func__ ,
                                                     "incorrect initialization of algorithm " );
  /* устанавливаем эллиптическую кривую */
   sctx->key.data = wc;

  /* При удалении ключа не нужно освобождать память из под параметров эллиптической кривой  */
   sctx->key.flags |= ak_skey_flag_data_nonfree;

 /* в заключение определяем указатели на методы */
  sctx->key.set_mask = ak_signkey_set_mask_multiplicative;
  sctx->key.remask = ak_signkey_remask_multiplicative;
  sctx->key.set_icode = ak_signkey_set_icode_multiplicative;
  sctx->key.check_icode = ak_signkey_check_icode_multiplicative;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_destroy( ak_signkey sctx )
{
  int error = ak_error_ok;
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                           "destroying a null pointer to digital signature secret key context" );
  if(( error = ak_skey_destroy( &sctx->key )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying of digital signature secret key" );
  if(( error = ak_hash_destroy( &sctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying hash function context" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_signkey_delete( ak_pointer sctx )
{
  if( sctx != NULL ) {
      ak_signkey_destroy(( ak_signkey ) sctx );
      free( sctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                   "using null pointer to digital signature secret key context" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param ptr указатель на область памяти, содержащей значение секретного ключа.
    @param size размер ключа в байтах.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_set_key( ak_signkey sctx, const ak_pointer ptr, const size_t size )
{
  int error = ak_error_ok;

  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to secret key context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to constant key value" );
  if( size > sctx->key.key.size ) return ak_error_message( ak_error_wrong_length, __func__,
                                                   "using constant buffer with unexpected length");
 /* присваиваем ключевой буффер */
  if(( error = ak_skey_set_ptr( &sctx->key, ptr, size, ak_true )) != ak_error_ok )
    return ak_error_message( error, __func__ , "incorrect assigning of key data" );

 /* в процессе присвоения ключа, он приводится по модулю и маскируется */
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param generator контекст генератора случайных чисел.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_set_key_random( ak_signkey sctx, ak_random generator )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to secret key context" );
  if( sctx->key.key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                     "using non initialized secret key context" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using null pointer to random number generator" );
 /* присваиваем секретный ключ */
  if(( error = ak_skey_set_random( &sctx->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a secret key context" );

 /* в процессе присвоения ключа, он приводится по модулю и маскируется */
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает секретному ключу электронной подписи значение, выработанное из
    пароля и инициализационного вектора с помощью алгоритма, регламентированого отечественными
    рекомендациями по стандартизации Р 50.1.111-2016.

    @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param pass пароль, представленный в виде строки символов.
    @param pass_size длина пароля в байтах
    @param salt инициализационный вектор, представленный в виде строки символов.
    @param salt_size длина инициализационного вектора в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_signkey_context_set_key_password( ak_signkey sctx, const ak_pointer pass,
                            const size_t pass_size, const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                     "using null pointer to secret key context" );
  if( sctx->key.key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                     "using non initialized secret key context" );
 /* вырабатываем секретный ключ */
  if(( error =
           ak_skey_set_password( &sctx->key, pass, pass_size, salt, salt_size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a secret key for hmac context" );

 /* в процессе присвоения ключа, он приводится по модулю и маскируется */
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает электронную подпись для \f$ e \f$ - вычисленного хеш-кода подписываемого
    сообщения и заданного случайного числа \f$ k \f$. Для этого

     - вычисляется точка \f$ C = [k]P\f$, где \f$ P \f$ точка, порождающая подгруппу простого
       порядка \f$ q \f$.
     - точка приводится к аффинной форме и для х-координаты точки \f$ C \f$ вычисляется значение
       \f$ r \equiv x \pmod{q}\f$.
     - вычисляется вторая половинка подписи  \f$ s \f$,
       удовлетворяющая сравнению \f$ s \equiv rd + ke \pmod{q}\f$.

    После этого
    формируется электронная подпись, представляющая собой конкатенацию векторов \f$ r||s \f$.

    \b Внимание! Входные параметры функции не проверяются.

    @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param k степень кратности точки \f$ P \f$; представляет собой вычет по модулю порядка
           группы точек эллиптической кривой;
           при вычислении подписи предполагается, что под вычет выделена память в количестве
           `wc->size` слов размера 64 бита, где `wc` используемая эллиптическая кривая.

    @param e хеш-код сообщения, для которого вырабатывается электронная подпись.
    @param out массив, куда помещается результат. Память под массив должна быть выделена заранее.  */
/* ----------------------------------------------------------------------------------------------- */
 void ak_signkey_context_sign_values( ak_signkey sctx, ak_uint64 *k, ak_pointer e, ak_pointer out )
{
 /* поскольку функция не экспортируется, мы оставляем все проверки функциям верхнего уровня */
  struct wpoint wr;
  ak_wcurve wc = ( ak_wcurve ) sctx->key.data;
  ak_uint64 *r = (ak_uint64 *)out, *s = ( ak_uint64 *)out + wc->size;

 /* вычисляем r */
  ak_wpoint_pow( &wr, &wc->point, k, wc->size, wc );
  ak_wpoint_reduce( &wr, wc );
  ak_mpzn_rem( r, wr.x, wc->q, wc->size );

 /* приводим r к виду Монтгомери и помещаем во временную переменную wr.x <- r */
  ak_mpzn_mul_montgomery( wr.x, r, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем значение s <- r*d (mod q) (сначала домножаем на ключ, потом на его маску) */
  ak_mpzn_mul_montgomery( s, wr.x, sctx->key.key.data, wc->q, wc->nq, wc->size );
  ak_mpzn_mul_montgomery( s, s, sctx->key.mask.data, wc->q, wc->nq, wc->size );

 /* приводим k к виду Монтгомери и помещаем во временную переменную wr.y <- k */
  ak_mpzn_mul_montgomery( wr.y, k, wc->r2q, wc->q, wc->nq, wc->size );

 /* приводим e к виду Монтгомери и помещаем во временную переменную wr.z <- e */
  ak_mpzn_rem( wr.z, (ak_uint64 *)e, wc->q, wc->size );
  if( ak_mpzn_cmp_ui( wr.z, wc->size, 0 )) ak_mpzn_set_ui( wr.z, wc->size, 1 );
  ak_mpzn_mul_montgomery( wr.z, wr.z, wc->r2q, wc->q, wc->nq, wc->size );

 /* вычисляем k*e (mod q) и вычисляем s = r*d + k*e (mod q) (в форме Монтгомери) */
  ak_mpzn_mul_montgomery( wr.y, wr.y, wr.z, wc->q, wc->nq, wc->size ); /* wr.y <- k*e */
  ak_mpzn_add_montgomery( s, s, wr.y, wc->q, wc->size );

 /* приводим s к обычной форме */
  ak_mpzn_mul_montgomery( s, s,  wc->point.z, /* для экономии памяти пользуемся равенством z = 1 */
                                 wc->q, wc->nq, wc->size );
 /* завершаемся */
  memset( &wr, 0, sizeof( struct wpoint ));
  sctx->key.remask( &sctx->key );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param hash последовательность байт, содержащая в себе хеш-код
    подписываемого сообщения.
    @param size размер хеш-кода, в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_hash_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_signkey_context_sign_hash( ak_signkey sctx,
                                                      ak_pointer hash, size_t size, ak_pointer out )
{
  ak_pointer pout = out;
  ak_buffer result = NULL;
  int error = ak_error_ok;
  ak_uint64 k[ak_mpzn512_size];
 /* нужен нам для доступа к системному генератору случайных чисел */
  ak_context_manager manager = NULL;

  if( sctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return NULL;
  }
  if( hash == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to hash value" );
    return NULL;
  }
  if( size != sizeof( ak_uint64 )*(( ak_wcurve )sctx->key.data)->size ) {
    ak_error_message( ak_error_wrong_length, __func__, "using hash value with wrong length" );
    return NULL;
  }

 /* получаем доступ к генератору случайных чисел */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                "using internal pointer to context manager" );
    return NULL;
  }

 /* вырабатываем случайное число */
  memset( k, 0, sizeof( ak_uint64 )*ak_mpzn512_size );
  if(( error = ak_mpzn_set_random_modulo( k, (( ak_wcurve )sctx->key.data)->q,
  (( ak_wcurve )sctx->key.data)->size, &manager->key_generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid generation of random value");
    return NULL;
  }

 /* определяем указатель на область памяти, в которую будет помещен результат вычислений */
  if( pout == NULL ) {
    if(( result = ak_buffer_new_size( 2*size )) != NULL )
      pout = result->data;
     else {
      ak_error_message( ak_error_get_value( ), __func__ , "wrong creation of result buffer" );
      goto lab_exit;
     }
  }

 /* и только теперь вычисляем электронную подпись */
  ak_signkey_context_sign_values( sctx, k, hash, pout );

 lab_exit:
   ak_ptr_wipe( k, sizeof( ak_uint64 )*ak_mpzn512_size, &sctx->key.generator );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_signkey_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_signkey_context_sign_ptr( ak_signkey sctx,
                                           const ak_pointer in, const size_t size, ak_pointer out )
{
  int error = ak_error_ok;
  ak_uint8 hash[64]; /* выбираем максимально возможный размер */

 /* необходимые проверки */
  if( sctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return NULL;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                   "using null pointer to signifying value" );
    return NULL;
  }
  if( sctx->ctx.hsize > 64 ) {
    ak_error_message( ak_error_wrong_length, __func__,
                                       "using hash function with very large hash code size" );
    return NULL;
  }

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, 64 );
  ak_hash_context_ptr( &sctx->ctx, in, size, hash );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return NULL;
  }

 return ak_signkey_context_sign_hash( sctx, hash, sctx->ctx.hsize, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param sctx контекст секретного ключа алгоритма электронной подписи.
    @param filename Строка с именем файла для которого вычисляется электронная подпись.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_signkey_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий вектор с электронной подписью. В случае
    возникновения ошибки возвращается NULL, при этом код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_signkey_context_sign_file( ak_signkey sctx, const char *filename, ak_pointer out )
{
  ak_uint8 hash[64];
  int error = ak_error_ok;

 /* необходимые проверки */
  if( sctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return NULL;
  }
  if( filename == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to file" );
    return NULL;
  }
  if( sctx->ctx.hsize > 64 ) {
    ak_error_message( ak_error_wrong_length, __func__,
                                            "using hash function with large hash code size" );
    return NULL;
  }

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, 64 );
  ak_hash_context_file( &sctx->ctx, filename, hash );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return NULL;
  }

 return ak_signkey_context_sign_hash( sctx, hash, sctx->ctx.hsize, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*                     функции для работы с открытыми ключами электронной подписи                  */
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция вычисляет открытый ключ (точку эллиптической кривой), соответствующую
    заданному секретному ключу.

    @param pctx Контекст открытого ключа электронной подписи
    @param sctx Контекст секретного ключа электронной подписи. Контекст должен быть предварительно
    проинициализирован и содержать некоторое ключевое значение.

    @return В случае успеха возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_create_signkey( ak_verifykey pctx, ak_signkey sctx )
{
  int error = ak_error_ok;
  ak_mpzn512 k, one = ak_mpzn512_one;

  if( pctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                            "using null pointer to digital signature public key context" );
  if( sctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                          "using a null pointer to digital signature secret key context" );

 /* устанавливаем OID алгоритма */
  if( strncmp( "sign256", sctx->key.oid->name, 7 ) == 0 ) {
    if(( pctx->oid = ak_oid_find_by_name( "verify256" )) == NULL )
      ak_error_message( ak_error_get_value(), __func__ ,
                                             "incorrect initialization of algorithm OID" );
  }
  if( strncmp( "sign512", sctx->key.oid->name, 7 ) == 0 ) {
    if(( pctx->oid = ak_oid_find_by_name( "verify512" )) == NULL )
      ak_error_message( ak_error_get_value(), __func__ ,
                                             "incorrect initialization of algorithm OID" );
  }
  if( strncmp( "sign256-gosthash94", sctx->key.oid->name, 18 ) == 0 ) {
    if(( pctx->oid = ak_oid_find_by_name( "verify256-gosthash94" )) == NULL )
      ak_error_message( ak_error_get_value(), __func__ ,
                                             "incorrect initialization of algorithm OID" );
  }

 /* инициализируем контекст функции хеширования */
  if(( error = ak_hash_create_oid( &pctx->ctx, sctx->ctx.oid )) != ak_error_ok )
    return ak_error_message( error, __func__, "invalid creation of hash function context");

 /* устанавливаем эллиптическую кривую */
  pctx->wc = ( ak_wcurve )sctx->key.data;

 /* теперь определяем открытый ключ */
  ak_mpzn_mul_montgomery( k, (ak_uint64 *)sctx->key.key.data, one,
                                                      pctx->wc->q, pctx->wc->nq, pctx->wc->size);
  ak_wpoint_pow( &pctx->qpoint, &pctx->wc->point, k, pctx->wc->size, pctx->wc );
  ak_mpzn_mul_montgomery( k, (ak_uint64 *)sctx->key.mask.data, one,
                                                      pctx->wc->q, pctx->wc->nq, pctx->wc->size);
  ak_wpoint_pow( &pctx->qpoint, &pctx->qpoint, k, pctx->wc->size, pctx->wc );
  ak_wpoint_reduce( &pctx->qpoint, pctx->wc );

  sctx->key.remask( &sctx->key );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа алгоритма электронной подписи.
    @return В случае успеха возвращается ноль (\ref ak_error_ok). В противном случае возвращается
    код ошибки.                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_verifykey_destroy( ak_verifykey pctx )
{
  int error = ak_error_ok;

  if( pctx == NULL )
    return ak_error_message( ak_error_null_pointer, __func__ ,
                                                      "using null pointer to public key context" );
  if(( error = ak_hash_destroy( &pctx->ctx )) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect destroying hash function context" );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа алгоритма электронной подписи.
    @return Функция возвращает NULL. В случае возникновения ошибки, ее код может быть получен с
    помощью вызова функции ak_error_get_value().                                                   */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_verifykey_delete( ak_pointer pctx )
{
  if( pctx != NULL ) {
      ak_verifykey_destroy(( ak_verifykey ) pctx );
      free( pctx );
     } else ak_error_message( ak_error_null_pointer, __func__ ,
                                   "using null pointer to digital signature public key context" );
 return NULL;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа.
    @param hash хеш-код сообщения, для которого проверяется электронная подпись.
    @param size размер хеш-кода, в байтах.
    @param sign электронная подпись, для которой выполняется проверка.
    @return Функция возыращает истину, если подпись верна. Если функция не верна или если
    возникла ошибка, то возвращается ложь. Код шибки может получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_verifykey_context_verify_hash( ak_verifykey pctx,
                                        const ak_pointer hash, const size_t size, ak_pointer sign )
{
  ak_mpzn512 v, z1, z2, u;
  struct wpoint cpoint, tpoint;
  ak_uint64 *r = NULL, *s = NULL;

  if( pctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                               "using a null pointer to secret key context" );
    return ak_false;
  }
  if( hash == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to hash value" );
    return ak_false;
  }
  if( size != sizeof( ak_uint64 )*(pctx->wc->size )) {
    ak_error_message( ak_error_wrong_length, __func__, "using hash value with wrong length" );
    return ak_false;
  }
  if( sign == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to sign value" );
    return ak_false;
  }
  r = ( ak_uint64 *)sign;
  s = ( ak_uint64 *)sign + pctx->wc->size;

  ak_mpzn_set( v, hash, pctx->wc->size );
  ak_mpzn_rem( v, v, pctx->wc->q, pctx->wc->size );
  if( ak_mpzn_cmp_ui( v, pctx->wc->size, 0 )) ak_mpzn_set_ui( v, pctx->wc->size, 1 );
  ak_mpzn_mul_montgomery( v, v, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

  /* вычисляем v (в представлении Монтгомери) */
  ak_mpzn_set_ui( u, pctx->wc->size, 2 );
  ak_mpzn_sub( u, pctx->wc->q, u, pctx->wc->size );
  ak_mpzn_modpow_montgomery( v, v, u, pctx->wc->q, pctx->wc->nq, pctx->wc->size ); // v <- v^{q-2} (mod q)

  /* вычисляем z1 */
  ak_mpzn_mul_montgomery( z1, s, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_mpzn_mul_montgomery( z1, z1, v, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_mpzn_mul_montgomery( z1, z1, pctx->wc->point.z, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

  /* вычисляем z2 */
  ak_mpzn_mul_montgomery( z2, r, pctx->wc->r2q, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_mpzn_sub( z2, pctx->wc->q, z2, pctx->wc->size );
  ak_mpzn_mul_montgomery( z2, z2, v, pctx->wc->q, pctx->wc->nq, pctx->wc->size );
  ak_mpzn_mul_montgomery( z2, z2, pctx->wc->point.z, pctx->wc->q, pctx->wc->nq, pctx->wc->size );

 /* сложение точек и проверка */
  ak_wpoint_pow( &cpoint, &pctx->wc->point, z1, pctx->wc->size, pctx->wc );
  ak_wpoint_pow( &tpoint, &pctx->qpoint, z2, pctx->wc->size, pctx->wc );
  ak_wpoint_add( &cpoint, &tpoint, pctx->wc );
  ak_wpoint_reduce( &cpoint, pctx->wc );
  ak_mpzn_rem( cpoint.x, cpoint.x, pctx->wc->q, pctx->wc->size );

  if( ak_mpzn_cmp( cpoint.x, r, pctx->wc->size )) return ak_false;
 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа.
    @param in область памяти для которой проверяется электронная подпись.
    @param size размер области памяти в байтах.
    @param sign электронная подпись, для которой выполняется проверка.
    @return Функция возыращает истину, если подпись верна. Если функция не верна или если
    возникла ошибка, то возвращается ложь. Код шибки может получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_verifykey_context_verify_ptr( ak_verifykey pctx, const ak_pointer in,
                                                               const size_t size, ak_pointer sign )
{
  ak_uint8 hash[64];
  int error = ak_error_ok;

 /* необходимые проверки */
  if( pctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return ak_false;
  }
  if( in == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                    "using null pointer to verifying value" );
    return ak_false;
  }
  if( pctx->ctx.hsize > 64 ) {
    ak_error_message( ak_error_wrong_length, __func__,
                                            "using hash function with large hash code size" );
    return ak_false;
  }

 /* вычисляем значение хеш-кода, а после подписываем его */
  memset( hash, 0, 64 );
  ak_hash_context_ptr( &pctx->ctx, in, size, hash );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return ak_false;
  }

 return ak_verifykey_context_verify_hash( pctx, hash, pctx->ctx.hsize, sign );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pctx контекст открытого ключа.
    @param in область памяти для которой проверяется электронная подпись.
    @param size размер области памяти в байтах.
    @param sign электронная подпись, для которой выполняется проверка.
    @return Функция возыращает истину, если подпись верна. Если функция не верна или если
    возникла ошибка, то возвращается ложь. Код шибки может получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_verifykey_context_verify_file( ak_verifykey pctx, const char *filename, ak_pointer sign )
{
  ak_uint8 hash[64];
  int error = ak_error_ok;

 /* необходимые проверки */
  if( pctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                 "using null pointer to secret key context" );
    return ak_false;
  }
  if( filename == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to filename" );
    return ak_false;
  }
  if( pctx->ctx.hsize > 64 ) {
    ak_error_message( ak_error_wrong_length, __func__,
                                            "using hash function with large hash code size" );
    return ak_false;
  }
  memset( hash, 0, 64 );
  ak_hash_context_file( &pctx->ctx, filename, hash );
  if(( error = ak_error_get_value()) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong calculation of hash value" );
    return ak_false;
  }

 return ak_verifykey_context_verify_hash( pctx, hash, pctx->ctx.hsize, sign );
}




/* ----------------------------------------------------------------------------------------------- */
/*                                         тестовые примеры                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_signkey_test( void )
{
 /* d = "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28"; */
  ak_uint64 key256[ak_mpzn256_size]  =
    { 0x1D19CE9891EC3B28LL, 0x1B60961F49397EEELL, 0x10ED359DD39A72C1LL, 0x7A929ADE789BB9BELL };

 /* d = BA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4 */
  ak_uint64 key512[ak_mpzn512_size]  =
    { 0xC62967821FA18DD4LL, 0xA2636B7BFD18AADFLL, 0x3322DAD2827E2714LL, 0x72E8123B2200A056LL,
      0x0EE7508E508B1020LL, 0x3091A0E851466970LL, 0xA40936D47756D7C9LL, 0x0BA6048AADAE241BLL };

 /* е = 2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5 */
  ak_uint64 e256[ak_mpzn256_size]  =
    { 0x67ECE6672B043EE5LL, 0xCE52032AB1022E8ELL, 0x88C09C52E0EEC61FLL, 0x2DFBC1B372D89A11LL };

 /* е = 3754F3CFACC9E0615C4F4A7C4D8DAB531B09B6F9C170C533A71D147035B0C5917184EE536593F4414339976C647C5D5A407ADEDB1D560C4FC6777D2972075B8C */
  ak_uint64 e512[ak_mpzn512_size]  =
    { 0xC6777D2972075B8CLL, 0x407ADEDB1D560C4FLL, 0x4339976C647C5D5ALL, 0x7184EE536593F441,
      0xA71D147035B0C591LL, 0x1B09B6F9C170C533LL, 0x5C4F4A7C4D8DAB53LL, 0x3754F3CFACC9E061 };

 /* k = 77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3 */
  ak_uint64 k256[ak_mpzn256_size]  =
    { 0x4FED924594DCEAB3LL, 0x6DE33814E95B7FE6LL, 0x2823C8CF6FCC7B95LL, 0x77105C9B20BCD312LL };

 /* k = 359E7F4B1410FEACC570456C6801496946312120B39D019D455986E364F365886748ED7A44B3E794434006011842286212273A6D14CF70EA3AF71BB1AE679F1 */
  ak_uint64 k512[ak_mpzn512_size]  =
    { 0xA3AF71BB1AE679F1LL, 0x212273A6D14CF70ELL, 0x4434006011842286LL, 0x86748ED7A44B3E79LL,
      0xD455986E364F3658LL, 0x946312120B39D019LL, 0xCC570456C6801496LL, 0x0359E7F4B1410FEALL };

  ak_uint8 sign256[64] =
    { 0x93, 0x04, 0xDC, 0x39, 0xFD, 0x43, 0xD0, 0x3A, 0xB8, 0x67, 0x27, 0xA4, 0x54, 0x35, 0x05, 0x74,
      0x19, 0xA4, 0xED, 0x6F, 0xD5, 0x9E, 0xCD, 0x80, 0x82, 0x14, 0xAB, 0xF1, 0xD2, 0x28, 0xAA, 0x41,
      0x40, 0x9C, 0xBF, 0xC5, 0xF6, 0x14, 0x80, 0x92, 0xDF, 0x31, 0xB6, 0x46, 0xF7, 0xD3, 0xD6, 0xBC,
      0x49, 0x02, 0xA6, 0x98, 0x5A, 0x23, 0x3C, 0x65, 0xA1, 0x42, 0x46, 0xBA, 0x64, 0x6C, 0x45, 0x01 };

  ak_uint8 sign512[128] =
    { 0x36, 0xAE, 0x73, 0xE1, 0x44, 0x93, 0xE1, 0x17, 0x33, 0x5C, 0x9C, 0xCD, 0xCB, 0x3B, 0xC9, 0x60,
      0x02, 0x85, 0x99, 0x06, 0xC9, 0x97, 0xC1, 0x9E, 0x1C, 0x0F, 0xB2, 0x86, 0x84, 0x55, 0x92, 0x54,
      0xD3, 0xAC, 0xFC, 0xA8, 0xEE, 0x78, 0x3C, 0x64, 0xC2, 0xDC, 0xE0, 0x2E, 0xC8, 0xA3, 0x12, 0xE5,
      0x9E, 0x68, 0x3C, 0x1E, 0x5E, 0x79, 0xDD, 0x23, 0x1A, 0x09, 0x81, 0xA0, 0x60, 0xFA, 0x86, 0x2F,
      0x4A, 0x5B, 0x3E, 0xE7, 0xBD, 0x53, 0x98, 0x2A, 0xB9, 0x9C, 0x91, 0x56, 0x1F, 0xEB, 0x6E, 0x6A,
      0x40, 0xCE, 0x70, 0x7F, 0xDF, 0x80, 0x60, 0x52, 0x62, 0xF3, 0xC4, 0xE8, 0x88, 0xE2, 0x3C, 0x82,
      0xF5, 0x2F, 0xD5, 0x33, 0xE9, 0xFB, 0x0B, 0x1C, 0x08, 0xBC, 0xAD, 0x8A, 0x77, 0x56, 0x5F, 0x32,
      0xB6, 0x26, 0x2D, 0x36, 0xA9, 0xE7, 0x85, 0x65, 0x8E, 0xFE, 0x6F, 0x69, 0x94, 0xB3, 0x81, 0x10 };

  int error = ak_error_ok, audit = ak_log_get_level();
  ak_bool result = ak_true;
  struct signkey sk;
  struct verifykey pk;
  ak_uint8 sign[128];
  char *str = NULL;

  if( audit >= ak_log_maximum )
   ak_error_message( ak_error_ok, __func__ , "testing digital signatures started" );

 /* первый пример из приложения А ГОСТ Р 34.10-2012. */
  if(( error = ak_signkey_create_streebog256( &sk,
    (ak_wcurve) &id_tc26_gost3410_2012_256_test_paramset )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature secret key" );
    return ak_false;
  }

  if(( error = ak_signkey_context_set_key( &sk, key256, sizeof( key256 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }

  memset( sign, 0, 64 );
  ak_signkey_context_sign_values( &sk, k256, e256, sign );
  if( ak_ptr_is_equal( sign, ( ak_pointer )sign256, 64 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature generation from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature generation from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr(( ak_pointer )sign256, 64, ak_true ))); free( str );
      ak_signkey_destroy( &sk );
      return ak_false;
    }

  if(( error = ak_verifykey_create_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }

  ak_signkey_destroy( &sk );
  if( ak_verifykey_context_verify_hash( &pk, e256, sizeof(e256), sign )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification from GOST R 34.10-2012 (for 256 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification from GOST R 34.10-2012 (for 256 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_verifykey_destroy( &pk );
      return ak_false;
  }
  ak_verifykey_destroy( &pk );

 /* второй пример из приложения А ГОСТ Р 34.10-2012. */
  if(( error = ak_signkey_create_streebog512( &sk,
    (ak_wcurve) &id_tc26_gost3410_2012_512_test_paramset )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature secret key" );
    return ak_false;
  }

  if(( error = ak_signkey_context_set_key( &sk, key512, sizeof( key512 ))) != ak_error_ok ) {
    ak_error_message( error, __func__, "incorrect assigning of key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }

  memset( sign, 0, 128 );
  ak_signkey_context_sign_values( &sk, k512, e512, sign );
  if( ak_ptr_is_equal( sign, ( ak_pointer )sign512, 128 )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature generation from GOST R 34.10-2012 (for 512 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature generation from GOST R 34.10-2012 (for 512 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 128, ak_true ))); free( str );
      ak_log_set_message(( str = ak_ptr_to_hexstr(( ak_pointer )sign512, 128, ak_true ))); free( str );
      ak_signkey_destroy( &sk );
      return ak_false;
    }

  if(( error = ak_verifykey_create_signkey( &pk, &sk )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "incorrect creation of digital signature public key" );
    ak_signkey_destroy( &sk );
    return ak_false;
  }

  ak_signkey_destroy( &sk );
  if( ak_verifykey_context_verify_hash( &pk, e512, sizeof(e512),  sign )) {
    if( audit >= ak_log_maximum )
      ak_error_message( ak_error_ok, __func__ ,
             "digital signature verification from GOST R 34.10-2012 (for 512 bit curve) is Ok" );
  } else {
      ak_error_message( ak_error_not_equal_data, __func__ ,
          "digital signature verification from GOST R 34.10-2012 (for 512 bit curve) is wrong" );
      ak_log_set_message(( str = ak_ptr_to_hexstr( sign, 64, ak_true ))); free( str );
      ak_verifykey_destroy( &pk );
      return ak_false;
  }
  ak_verifykey_destroy( &pk );

  if( !result ) ak_error_message( ak_error_get_value(), __func__ ,
                                                         "incorrect testing digital signatures" );
   else if( audit >= ak_log_maximum ) ak_error_message( ak_error_get_value(), __func__ ,
                                                "testing digital signatures ended successfully" );
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_sign.c  */
/* ----------------------------------------------------------------------------------------------- */
