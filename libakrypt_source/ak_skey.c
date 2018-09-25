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
/*   ak_skey.c                                                                                     */
/* ----------------------------------------------------------------------------------------------- */
 #include <time.h>
 #include <ak_skey.h>
 #include <ak_tools.h>
 #include <ak_compress.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует поля структуры, выделяя необходимую память. Всем полям
    присваиваются значения по-умолчанию.

    \b Внимание! После создания, указатели на методы cекретного ключа инициализируются для
    работы с аддитивной по модулю 2 маской. В слуае необходимости использования другого способа
    маскирования, функции должны переопределятиься в производящих функциях для конктерного
    типа секретного ключа.

    Кроме того, остаются неопределенными поля data, resource и oid. Перечисленные поля и методы
    также должны определяться далее, в производящих функциях.

    @param skey контекст (структура struct skey) секретного ключа. Память под контекст
    должна быть выделена заранее.
    @param size размер секретного ключа в байтах
    @param isize размер контрольной суммы ключа в байтах
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_create( ak_skey skey, size_t size, size_t isize )
{
  int error = ak_error_ok;
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                              "using a zero length for key size" );
  if( isize == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                        "using a zero length for integrity code" );
 /* Инициализируем данные базовыми значениями */
  if(( error = ak_buffer_create_function_size( &skey->key,
                       /* в настоящий момент для выделения памяти используются стандартные функции */
                                               malloc, free,
                                               size )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a secret key buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_buffer_create_size( &skey->mask, size )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a key mask buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_buffer_create_size( &skey->icode, isize )) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation a integrity code buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  skey->data = NULL;
  memset( &(skey->resource), 0, sizeof( union resource ));

 /* инициализируем генератор масок */
  if(( error = ak_random_create_lcg( &skey->generator )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "wrong creation of random generator" );
    ak_skey_destroy( skey );
    return error;
  }

 /* номер ключа генерится случайным образом. изменяется позднее, например,
                                                           при считывания с файлового носителя */
  if(( error = ak_buffer_create_size( &skey->number,
                           ak_libakrypt_get_option( "key_number_length" ))) != ak_error_ok ) {
    ak_error_message( error, __func__ ,"wrong creation key number buffer" );
    ak_skey_destroy( skey );
    return error;
  }
  if(( error = ak_skey_set_unique_number( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "invalid creation of key number" );
    ak_skey_destroy( skey );
    return error;
  }
  /* OID ключа устанавливается производящей функцией */
  skey->oid = NULL;

  /* После создания ключа все его флаги не определены */
  skey->flags = 0;

 /* в заключение определяем указатели на методы.
    по умолчанию используются механизмы для работы с аддитивной по модулю 2 маской.

    Указатели на функции, отличные от данных, должны устанавливаться при создании
    конкретного типа ключа, например, конкретного алгоритма блочного шифрования */
  skey->set_mask = ak_skey_set_mask_xor;
  skey->remask = ak_skey_remask_xor;
  skey->set_icode = ak_skey_set_icode_xor;
  skey->check_icode = ak_skey_check_icode_xor;
  skey->update = ak_skey_update_compress_xor;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция удаляет все выделенную память и уничтожает хранившиеся в ней значения.

    @param skey контекст секретного ключа
    @return Функция возвращает \ref ak_error_ok (ноль) в случае успеха.
    В противном случае возвращается код ошибки.                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_destroy( ak_skey skey )
{
  if( skey == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "destroying a null pointer to secret key" );
    return ak_error_null_pointer;
  }

 /* удаляем данные */
  ak_buffer_wipe( &(skey->key), &skey->generator );
  ak_buffer_destroy( &(skey->key ));
  memset( &(skey->key), 0, sizeof( struct buffer ));

  ak_buffer_wipe( &(skey->mask), &skey->generator );
  ak_buffer_destroy( &(skey->mask ));
  memset( &(skey->mask), 0, sizeof( struct buffer ));

  ak_buffer_wipe( &(skey->icode), &skey->generator );
  ak_buffer_destroy( &(skey->icode ));
  memset( &(skey->icode), 0, sizeof( struct buffer ));

  ak_random_destroy( &skey->generator );
  if( skey->data != NULL )
   /* удаляем память только при установленном флаге */
    if( !((skey->flags)&ak_skey_flag_data_nonfree )) free( skey->data );

  ak_buffer_destroy( &skey->number );
  skey->oid = NULL;
  memset( &(skey->resource), 0, sizeof( union resource ));
  skey->flags = 0;

 /* обнуляем указатели */
  skey->set_mask = NULL;
  skey->remask = NULL;
  skey->set_icode = NULL;
  skey->check_icode = NULL;
  skey->update = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Выработанный функцией номер является уникальным (в рамках библиотеки) и однозначно идентифицирует
    секретный ключ. Данный идентификатор может сохраняться вместе с ключом.

    @param skey контекст секретного ключа, для клоторого вырабатывается уникальный номер
    @return В случае успеха функция возвращает k_error_ok (ноль). В противном случае, возвращается
    номер ошибки.                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_unique_number( ak_skey skey )
{
  time_t tm = 0;
  size_t len = 0;
  struct hash ctx;
  ak_uint8 out[32];
  int error = ak_error_ok;
  const char *version =  ak_libakrypt_version();

 /* стандартные проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                         __func__ , "using a null pointer to secret key" );
  if(( error = ak_hash_create_streebog256( &ctx )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong creation of hash function context" );

 /* заполняем стандартное начало вектора */
  memset( out, 0, 32 );
  len = strlen( version );
  memcpy( out, version, len ); /* сначала версия библиотеки */
  tm = time( NULL );
  memcpy( out+len, &tm, sizeof(tm) ); /* потом время генерации номера ключа */
  len += sizeof( time_t );
  if( len < 32 ) skey->generator.random( &skey->generator, out+len, 32 - len ); /* добавляем мусор */

 /* вычисляем номер и очищаем память */
  ak_hash_context_ptr( &ctx, out, 32, out );
  if(( error = ak_buffer_set_ptr( &skey->number,
                          out, ak_min( 32, skey->number.size ), ak_true )) != ak_error_ok )
    return ak_error_message( ak_error_write_data, __func__ , "wrong assigning key number" );

  ak_hash_destroy( &ctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Проверка параметров контекста секретного ключа

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 inline int ak_skey_check( ak_skey skey )
{
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to secret key" );
 /* проверяем длину ключа */
  if( skey->key.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                           "using a key buffer with zero length" );
  if( skey->key.size%8 != 0 ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                          "using a key buffer with wrong length" );
 /* проверяем маску */
  if( skey->mask.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                                 __func__ , "using a null pointer to key buffer" );
  if( skey->mask.size != skey->key.size ) return ak_error_message( ak_error_wrong_length,
                                     __func__ , "using mask and key buffer with diffenent sizes" );
 /* проверяем контрольную сумму */
  if( skey->icode.data == NULL ) return ak_error_message( ak_error_null_pointer,
                                               __func__ , "using a null pointer to icode buffer" );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вырабатывает случайный вектор \f$ v \f$ длины, совпадающей с длиной ключа,
    и заменяет значение ключа \f$ k \f$ на величину \f$ k \oplus v \f$.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_mask_xor( ak_skey skey )
{
  size_t idx = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* создаем маску*/
  if(( error = skey->generator.random( &skey->generator,
                                           skey->mask.data, skey->mask.size )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong mask generation for key buffer" );

 /* накладываем маску на ключ */
  for( idx = 0; idx < ( skey->key.size >> 3 ); idx++ )
     ((ak_uint64 *) skey->key.data)[idx] ^= ((ak_uint64 *) skey->mask.data)[idx];

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_update_compress_xor( ak_skey skey, ak_pointer ptr , const size_t size )
{
  size_t idx = 0;
  ak_uint8 tval[128];
  int error = ak_error_ok;
  ak_compress comp = ( ak_compress )ptr;

  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using a null pointer to secret key" );
  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                  "using a null pointer to compress context key" );
 /* выполняем проверку длины ключа */
  if( skey->key.size > 128 ) return ak_error_message( ak_error_undefined_value, __func__ ,
                                                            "using a very large secret key size" );
 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* снимаем маску */
  for( idx = 0; idx < (skey->key.size >> 3); idx++ ) ((ak_uint64 *)tval)[idx] =
                        ((ak_uint64 *) skey->key.data)[idx] ^ ((ak_uint64 *) skey->mask.data)[idx];

  if(( error = ak_compress_update( comp, tval, ak_min( skey->key.size, size ))) != ak_error_ok )
    ak_error_message( error, __func__ , "incorrect updating compress context" );
  skey->generator.random( &skey->generator, tval, skey->key.size );

 return error;
}


/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет новый случайный вектор \f$ v \f$ и изменяет значение
    значение ключа, снимая старую маску и накладывая новую.

    @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_remask_xor( ak_skey skey )
{
  size_t idx = 0;
  ak_uint64 newmask = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* накладываем маску */
  for( idx = 0; idx < ( skey->key.size >> 3 ); idx++ ) {
     if( skey->generator.random( &skey->generator, &newmask, sizeof( ak_uint64 )) == ak_error_ok )
    {
       ((ak_uint64 *) skey->mask.data )[idx] ^= newmask;
       ((ak_uint64 *) skey->key.data)[idx] ^= ((ak_uint64 *) skey->mask.data )[idx];
       ((ak_uint64 *) skey->mask.data )[idx] = newmask;
    } else return ak_error_message( ak_error_undefined_value,
                                                       __func__ , "wrong random mask generation" );
  }

 /* удаляем старое */
  memset( &newmask, 0, sizeof( ak_uint64 ));
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Нелинейная перестановка в кольце \f$ \mathbb Z_{2^{64}} \f$

    Функция реализует преобразование, которое можно рассматривать как нелинейную
    перестановку \f$ \pi \f$ элементов кольца \f$ \mathbb Z_{2^{64}} \f$, задаваемое следующим образом.

    Пусть \f$ \overline x \f$ есть побитовое инвертирование переменной \f$ x \f$,
    a \f$ f(x,y)\in\mathbb Z[x]\f$ многочлен,
    определяемый равенством \f$ f(x,y) = \frac{1}{2}\left( (x+y)^2 + x + 3y \right)\f$. Тогда
    перестановка \f$ \pi \f$ определяется равенством
    \f$ \pi(x,y) = const \oplus
                    \left\{ \begin{array}{ll}
                              f(x,y), & x+y < 2^{32}, \\
                              \overline{f(\overline{x},\overline{y})}, & 2^{32} \le x+y < 2^{64}.
                            \end{array}
                    \right.\f$

    @param xv Величина \f$ x \in \mathbb Z_{2^{32}} \f$
    @param yv Величина \f$ y \in \mathbb Z_{2^{32}} \f$
    @return Значение перестановки \f$ \pi \f$                                                      */
/* ----------------------------------------------------------------------------------------------- */
 static ak_uint64 ak_skey_icode_permutation( const ak_uint32 xv, const ak_uint32 yv )
{
  ak_uint32 x = xv, y = yv, carry = 0;
  ak_uint64 s =  ( ak_uint64 )x + y, more = s&0x100000000, result = 0;

  if( more ) { x = ~x; y = ~y; s = ( ak_uint64 )x + y; }
  result = y; result *= 3; result += x;
  s *= s; result += s; if( result < s ) carry = 1;

  result >>= 1;
  if( carry ) result ^= 0x8000000000000000L;
  if( more ) result = ~result;
 return result^0xC5BF891B4EF6AA79L; // константа есть \sqrt{\pi}
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Реализация алгоритма вычисления контрольной суммы для xor-маски ключа */
 static void ak_skey_icode_xor_sum( ak_skey skey, ak_uint64 *result )
{
  size_t i = 0;
  for( i = 0; i < (skey->key.size >> 2); i+=4 ) {
     ak_uint32 x = ((ak_uint32 *) skey->key.data)[i],
               y = ((ak_uint32 *) skey->key.data)[i+2];
     x ^= ((ak_uint32 *) skey->key.data)[i+1];
     y ^= ((ak_uint32 *) skey->key.data)[i+3];
     x ^= ((ak_uint32 *) skey->mask.data)[i];
     x ^= ((ak_uint32 *) skey->mask.data)[i+1];
     y ^= ((ak_uint32 *) skey->mask.data)[i+2];
     y ^= ((ak_uint32 *) skey->mask.data)[i+3];
     *result += ak_skey_icode_permutation( x, y );
  }
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае успеха функция возвращает ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_icode_xor( ak_skey skey )
{
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using invalid secret key" );

 /* теперь, собственно вычисление контрольной суммы */
  memset( skey->icode.data, 0, skey->icode.size );
  ak_skey_icode_xor_sum( skey, (ak_uint64 *)skey->icode.data );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param skey Указатель на контекст секретного ключа. Длина ключа (в байтах)
    должна быть кратна 8.

    @return В случае совпадения контрольной суммы ключа функция возвращает истину (\ref ak_true).
    В противном случае, возвращается ложь (\ref ak_false).                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_skey_check_icode_xor( ak_skey skey )
{
  ak_uint64 result = 0;
  int error = ak_error_ok;

 /* выполняем стандартные проверки */
  if(( error = ak_skey_check( skey )) != ak_error_ok ) {
    ak_error_message( error, __func__ , "using invalid secret key" );
    return ak_false;
  }
  if( skey->icode.size != 8 ) {
    ak_error_message( ak_error_wrong_length, __func__ , "wrong length of icode buffer" );
    return ak_false;
  }

 /* теперь, собственно вычисление контрольной суммы */
  ak_skey_icode_xor_sum( skey, &result );
 /* и сравнение */
  if( memcmp( skey->icode.data, &result, 8 )) return ak_false;
   else return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу заданное значение, размер которого определяется размером секретного
    ключа. В зависимости от значения флага cflag при присвоении данные могут копироваться в контекст
    секретного ключа, либо в контекст может передаваться владение указателем на данные.
    В этом случае поведение функции аналогично поведению функции ak_buffer_set_ptr().

    \b Внимание! В процессе работы ключ может изменять свое значение при наложении/изменении маски,
    поэтому если контекст ключа использует внешний буффер (cflag == ak_false), внешний буффер должен
    быть доступен все время существования ключа. Контроль за существованием внешнего буффера возлагается
    на фрагмент кода, вызывающий данную функцию.

    Основная область применения функции заключается в реализации тестовых примеров, для которых
    значение ключа является заранее известной константой.

    @param skey Контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param ptr Указатель на данные, которые будут интерпретироваться в качестве значения ключа.
    @param size Размер данных, на которые указывает ptr (размер в байтах).
    Если величина size меньше, чем размер выделенной памяти под секретный ключ, то копируется
    только size байт (остальные заполняются нулями). Если size больше, чем количество выделенной памяти
    под ключ, то копируются только младшие байты, в количестве `key.size` байт.

    @param cflag Флаг передачи владения укзателем ptr. Если cflag ложен (ak_false), то физического
    копирования данных не происходит: внутренний буфер лишь указывает на размещенные в другом месте
    данные, но не владеет ими. Если cflag истиннен (ak_true), то происходит выделение памяти и
    копирование данных в эту память (размножение данных).

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_ptr( ak_skey skey, const ak_pointer ptr, const size_t size, const ak_bool cflag )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using non initialized secret key context" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                        "using a null pointer to secret key data" );
 /* обнуляем ключ и присваиваем буффер */
  memset( skey->key.data, 0, skey->key.size );
  if(( error =
      ak_buffer_set_ptr( &skey->key, ptr, ak_min( size, skey->key.size ), cflag )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong assigning a secret key data" );

 /* маскируем ключ и вычисляем контрольную сумму */
  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );

  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_skey_flag_set_key;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу случайное (псевдо-случайное) значение, размер которого определяется
    размером секретного ключа. Способ выработки ключевого значения определяется используемым
    генератором случайных (псевдо-случайных) чисел.

    @param skey контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param generator контекст генератора псевдо-случайных чисел.

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_random( ak_skey skey, ak_random generator )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using non initialized secret key context" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using a null pointer to random number generator" );
 /* присваиваем буффер и маскируем его */
  if(( error = ak_buffer_set_random( &skey->key, generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "wrong generation a secret key data" );

  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                            __func__ , "wrong secret key masking" );
  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                 __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_skey_flag_set_key;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция присваивает ключу значение, выработанное из заданного пароля при помощи алгоритма,
    описанного  в рекомендациях по стандартизации Р 50.1.111-2016.
    Пароль должен быть непустой строкой символов в формате utf8.

    @param skey контекст секретного ключа. К моменту вызова функции контекст должен быть
    инициализирован.
    @param pass пароль, представленный в виде строки символов.
    @param pass_size длина пароля в байтах
    @param salt пароль, представленный в виде строки символов.
    @param salt_size длина пароля в байтах

    @return В случае успеха возвращается значение \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_skey_set_password( ak_skey skey, const ak_pointer pass, const size_t pass_size,
                                                     const ak_pointer salt, const size_t salt_size )
{
  int error = ak_error_ok;

 /* выполняем необходимые проверки */
  if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using a null pointer to secret key" );
  if( skey->key.size == 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                       "using non initialized secret key context" );
  if( pass == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                               "using a null pointer to password" );
  if( !pass_size ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                              "using a password with zero length" );
 /* присваиваем буффер и маскируем его */
  if(( error = ak_hmac_pbkdf2_streebog512( pass, pass_size, salt, salt_size,
                                  ak_libakrypt_get_option("pbkdf2_iteration_count"),
                                                 skey->key.size, skey->key.data )) != ak_error_ok )
                  return ak_error_message( error, __func__ , "wrong generation a secret key data" );

  if(( error = skey->set_mask( skey )) != ak_error_ok ) return  ak_error_message( error,
                                                           __func__ , "wrong secret key masking" );
  if(( error = skey->set_icode( skey )) != ak_error_ok ) return ak_error_message( error,
                                                __func__ , "wrong calculation of integrity code" );

 /* устанавливаем флаг того, что ключевое значение определено.
    теперь ключ можно использовать в криптографических алгоритмах */
  skey->flags |= ak_skey_flag_set_key;

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                      ak_skey.c  */
/* ----------------------------------------------------------------------------------------------- */
