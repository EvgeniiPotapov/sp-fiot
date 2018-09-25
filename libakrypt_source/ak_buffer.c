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
/*   ak_buffer.c                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_buffer.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct buffer в значения по-умолчанию.

    @param buff указатель на структуру struct buffer
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_create( ak_buffer buff )
{
  if( buff == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to a buffer" );
    return ak_error_null_pointer;
  }
  buff->data = NULL; buff->size = 0; buff->flag = ak_false;
  buff->alloc = malloc; /* по-умолчанию, используются обычные функции */
  buff->free = free;    /* выделения/освобождения памяти */
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff указатель на структуру struct buffer
    @param size размер инициализируемого буффера в байтах

    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_create_size( ak_buffer buff, const size_t size )
{
  int error = ak_error_ok;
  if(( error = ak_buffer_create( buff )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong buffer context creation" );
    return error;
  }
  if(( error = ak_buffer_alloc( buff, size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong memory allocation for buffer context" );
    ak_buffer_destroy( buff );
    return error;
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff указатель на структуру struct buffer
    @param falloc указатель на функцию выделения памяти
    @param ffree указатель на функцию освобождения памяти
    @param size размер выделяемой под буффер памяти (в байтах)
    @return Функция возвращает указатель на созданный буффер. Если произошла ошибка,
    то возвращается NULL                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_create_function_size( ak_buffer buff, ak_function_alloc *falloc,
                                                        ak_function_free *ffree, const size_t size )
{
  int error = ak_error_ok;
 /* создаем буффер со значениями по умолчанию */
  if(( error = ak_buffer_create( buff )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong buffer context creation" );
    return error;
  }
 /* меняем указатели на функции выделения и очистки памяти */
  buff->free = ffree; buff->alloc = falloc;
 /* только теперь реально выделяем память под данные */
  if(( error = ak_buffer_alloc( buff, size )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong memory allocation for buffer context" );
    ak_buffer_destroy( buff );
    return error;
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает указатель на структуру struct buffer, устанавливает поля этой структуры
    в значения по-умолчанию и возвращает указатель на созданную структуру.
    @return Если указатель успешно создан, то он и возвращается. В случае возникновения ошибки
    возвращается NULL.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_buffer_new( void )
{
  ak_buffer buff = ( ak_buffer ) malloc( sizeof( struct buffer ));
  if( buff != NULL ) ak_buffer_create( buff );
   else ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
  return buff;
}


/* ----------------------------------------------------------------------------------------------- */
/*! @param ptr указатель на данные, помещаемые в буффер. Если указатель не определен, то
    возвращается код ошибки.
    @param size размер помещаемых в буффер данных. Если size равен нулю, то
    возвращается код ошибки.
    @param flag флаг владения данными. Если он истинен, то данные копируются в область памяти,
    которой владеет буфер. Если флаг ложен, то буфер просто содержит указатель на данные,
    которыми он не владеет.
    @return Функция возвращает указатель на созданный буффер. Если произошла ошибка,
    то возвращается NULL                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_buffer_new_ptr( const ak_pointer ptr, const size_t size, const ak_bool flag )
{
  ak_buffer buff = NULL;
  if( ptr == NULL ) { /* присвоение не существующих данных */
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a data" );
   return NULL;
  }
  if( size <= 0 ) { /* присвоение данных неопределенной длины */
   ak_error_message( ak_error_zero_length, __func__, "use a data with non positive length" );
   return NULL;
  }
  if( ak_buffer_set_ptr( buff = ak_buffer_new(), ptr, size, flag ) == ak_error_ok ) return buff;
 return ( buff = ak_buffer_delete( buff ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Размер создаваемого буффера определяется длиной строки символов.

   @param hexstr указатель на строку символов, содержащую шестнадцатеричную форму записи данных
   @return Функция возвращает указатель на созданный буффер. Если произошла ошибка,
   то возвращается NULL                                                                            */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_buffer_new_hexstr( const char *hexstr )
{
  ak_buffer buff = NULL;
  if( hexstr == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a hex string" );
   return NULL;
  }
  if( ak_buffer_set_hexstr( buff = ak_buffer_new(), hexstr ) == ak_error_ok ) return buff;
  return ( buff = ak_buffer_delete( buff ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! Перед конвертацией данных, функция создает массив фиксированной длины. Если
    данные превышают указанный размер, то возвращается ошибка.

   @param hexstr указатель на строку символов, содержащую шестнадцатеричную форму записи данных
   @param size Размер создаваемого буффера (в байтах).
   Если исходная строка требует больший размер, то возбуждается ошибка.
   @param reverse Последовательность считывания байт в память. Если reverse равно \ref ak_false
   то первые байты строки (с младшими индексами) помещаются в младшие адреса, а старшие байты -
   в старшие адреса памяти. Если reverse равно \ref ak_true, то производится разворот,
   то есть обратное преобразование при котором элементы строки со старшиси номерами помещаются
   в младшие разряды памяти (такое представление используется при считывании больших целых чисел).

   @return Функция возвращает указатель на созданный буффер. Если произошла ошибка,
   то возвращается NULL, код ошибки может быть получен с помощью вызова ak_error_get_value()       */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_buffer_new_hexstr_size( const char *hexstr , const size_t size, const ak_bool reverse )
{
  ak_buffer buff = NULL;
  if( hexstr == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a hex string" );
   return NULL;
  }
  if( size == 0 ) {
    ak_error_message( ak_error_zero_length, __func__, "using zero value for length of buffer" );
    return NULL;
  }
  if(( buff = ak_buffer_new_size( size )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong creation of a new buffer" );
    return NULL;
  }

  if( ak_hexstr_to_ptr( hexstr, ak_buffer_get_ptr( buff ), size, reverse ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong convertaion of hex string" );
    return( buff = ak_buffer_delete( buff ));
  }
 return buff;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param str указатель на строку символов
    @return Функция возвращает указатель на созданный буффер. Если произошла ошибка,
    то возвращается NULL                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_buffer_new_str( const char *str )
{
  ak_buffer buff = NULL;
  if( str == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a string" );
   return NULL;
  }
  if( ak_buffer_set_str( buff = ak_buffer_new(), str ) == ak_error_ok ) return buff;
  return ( buff = ak_buffer_delete( buff ));
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param size размер выделяемой памяти в байтах
    @return Функция возвращает указатель на созданный буффер. Если произошла ошибка,
    то возвращается NULL                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_buffer_new_size( const size_t size )
{
  ak_buffer buff = NULL;
  int error = ak_error_ok;

  if( size <= 0 ) {
    ak_error_message( ak_error_wrong_length, __func__, "create a buffer with non positive length" );
    return NULL;
  }

  if( ak_buffer_alloc( buff = ak_buffer_new(), size ) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong memory alloction" );
    return buff = ak_buffer_delete( buff );
  }

  memset( buff->data, 0, buff->size );
 return buff;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff указатель на структуру struct buffer для которого освобождается память.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_free( ak_buffer buff )
{
  if( buff == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
   return ak_error_null_pointer;
  }
  if( buff->flag == ak_true ) {
    memset( buff->data, 0, buff->size );
    buff->free( buff->data );
  }
  buff->data = NULL; buff->size = 0; buff->flag = ak_false;
  return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff указатель на структуру struct buffer, в которой выделяется память
    @param size размер выделяемой памяти в байтах
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_alloc( ak_buffer buff, const size_t size )
{
  ak_uint8 *ptr = NULL;
  int error = ak_error_ok;

 /* сли новый размер равен нулю, то просто очищаем память */
  if( size == 0 ) {
    if(( error = ak_buffer_free( buff )) != ak_error_ok )
      ak_error_message( error, __func__, "incorrect buffer memory destroying");
    return error;
  }
 /* если буфер не владеет памятью или ее недостаточно, то выделяем новую память */
  if(( buff->flag == ak_false) || ( size > buff->size )) {

    if(( ptr = buff->alloc( size )) == NULL )
      return ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
    memset( ptr, 0, size );
    if(( error = ak_buffer_free( buff )) != ak_error_ok ) {
      ak_error_message( error, __func__, "incorrect buffer memory destroying");
      free( ptr );
      return error;
    }
    buff->data = ptr;
    buff->flag = ak_true;
    buff->size = size;
  } else memset( buff->data, 0, buff->size );
 return ak_error_ok;

 /*
  if( size > 0 ) {
    if(( ptr = buff->alloc( size )) == NULL ) {
     ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
     return ak_error_out_of_memory;
    }
    memset( ptr, 0, size );
  }
  if( ak_buffer_free( buff ) != ak_error_ok ) {
    int local_error = ak_error_get_value();
    ak_error_message( local_error, __func__, "incorrect memory cleaning" );
    return local_error;
  }
  buff->data = ptr;
  buff->flag = ak_true;
  if( size > 0 ) buff->size = size;
    else buff->size = 0;
  return ak_error_ok;
 */
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff указатель на структуру struct buffer
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_destroy( ak_buffer buff )
{
  if( buff == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
   return ak_error_null_pointer;
  }
  ak_buffer_free( buff );
  buff->alloc = NULL; buff->free = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает все внутренние поля, уничтожает буфер (структуру struct buffer)
    присваивает указателю значение NULL.

    @param buff указатель на структуру struct buffer
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_buffer_delete( ak_pointer buff )
{
  if( buff != NULL ) {
   ak_buffer_destroy( buff );
   free( buff );
  } else ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
  return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция помещает в буффер данные на которые указывает указатель ptr. Размер данных, в байтах,
    передается в переменной size.
    Если cflag ложен (ak_false), то физического копирования данных не происходит: буфер лишь
    указывает на размещенные в другом месте данные, но не владеет ими.
    Если cflag истиннен (ak_true), то происходит выделение памяти и копирование данных
    в эту память (размножение данных).

    Простейший пример помещения данных в буфер без копирования
 \code
    const ak_uint8 data[8] = { 'w', 'e', 'l', 'c', 'o', 'm', 'e', 0 };
    ak_buffer buffer = ak_buffer_new();
    ak_buffer_set_ptr( buffer, data, 8, ak_false );
    buffer = ak_buffer_delete( buffer ); // в этот момент удаление массива данных data не происходит
                                     // однако указатель buffer уничтожается и приравнивается к NULL
 \endcode

    @param buff указатель на структуру struct buffer
    @param ptr указатель на данные, помещаемые в буффер. Если указатель не определен, то
    возвращается код ошибки.
    @param size размер помещаемых в буффер данных. Если ptr_size равен нулю, то
    возвращается код ошибки.
    @param cflag флаг владения данными. Если он истинен, то происходит выделение памяти и
    копирование данных в эту область. В противном случае копирования данных не происходит.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_set_ptr( ak_buffer buff, const ak_pointer ptr, const size_t size, const ak_bool cflag )
{
  if( buff == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
   return ak_error_null_pointer;
  }
  if( ptr == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a data" );
   return ak_error_null_pointer;
  }
  if( size <= 0 ) {
   ak_error_message( ak_error_zero_length, __func__, "use a data with zero or negative length" );
   return ak_error_zero_length;
  }
  if( cflag == ak_false ) {
        ak_buffer_free( buff );
        buff->data = ( ak_uint8 *) ptr;
        buff->size = size;
        buff->flag = ak_false;
  } else {
           if( ak_buffer_alloc( buff, size )) {
             ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
             return ak_error_out_of_memory;
           }
           memcpy( buff->data, ptr, size );
         }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_set_random( ak_buffer buff, ak_random generator )
{
  int result = ak_error_ok;

  if( buff == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to buffer context" );
    return ak_error_null_pointer;
  }
  if( generator == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to a random generator" );
    return ak_error_null_pointer;
  }
  if( buff->data == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using null pointer to internal buffer" );
    return ak_error_null_pointer;
  }
  if( generator->random( generator, buff->data, buff->size ) != ak_error_ok ) {
    ak_error_message( ak_error_write_data, __func__, "incorrect randomizing internal buffer" );
    memset( buff->data, 0, buff->size );
    result = ak_error_write_data;
  }
 return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выделяет память под строку на которую указывает str, и копирует
    строку в память буфера. Размер стоки определяется с помощью вызова strlen().

    @param buff буфер, в который происходит копирование
    @param str копируемая строка
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_set_str( ak_buffer buff, const char *str )
{
  size_t len = 0;
  if( buff == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
   return ak_error_null_pointer;
  }
  if( str == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a string" );
   return ak_error_null_pointer;
  }

  len = strlen( (char *)str );
  if( ak_buffer_alloc( buff, 1+len )) {
   ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
   return ak_error_out_of_memory;
  }
  memcpy( buff->data, str, len );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция интерпретирует входную строку символов hexstr как шестнадцатеричную запись
    последовательности байт. Функция выделяет необходимую память и присваивает буфферу
    двоичные данные, содержащиеся в строке hexstr. Если строка содержит символы, отличные от
    0, 1, .. 9, a, .. f, то соответствующий символу байт заменяется нулем, и выставляется
    код ошибки, равный ak_error_undefined_value.

    @param buff буфер, к который происходит присовение
    @param hexstr строка в шестнадцатеричной записи
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_set_hexstr( ak_buffer buff, const char *hexstr )
{
  size_t len = 0;

  if( buff == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
   return ak_error_null_pointer;
  }
  if( hexstr == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a hex string" );
   return ak_error_null_pointer;
  }

  len = strlen( (char *)hexstr );
  if( len&1 ) len++;
  len >>= 1;
  if( ak_buffer_alloc( buff, len )) {
    ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
    return ak_error_out_of_memory;
  }

  ak_error_set_value( ak_error_ok );
 return ak_hexstr_to_ptr( hexstr, buff->data, len, ak_false );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразует содержимое буффера в строку символов и возвращает эту строку.
    Под строку выделяется память, которая должна быть удалена пользователем самостоятельно.
    @param buff буффер, преобразование которого производится.
    @param reverse Последовательность вывода байт в строку. Если reverse равно \ref ak_false,
    то байты выводятся начиная с младшего к старшему.  Если reverse равно \ref ak_true, то байты
    выводятся начиная от старшего к младшему (такой способ вывода принят при стандартном выводе
    чисел: сначала старшие разряды, потом младшие).

    @return указатель на область памяти, в которой хранится выделенная строка, либо NULL.
    Если при преобразовании произошла ошибка, ее код содержится в переменной ak_errno.             */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_buffer_to_hexstr( const ak_buffer buff , const ak_bool reverse )
{
  if( buff == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
   return ak_null_string;
  }
  return ak_ptr_to_hexstr( buff->data, buff->size, reverse );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff Указатель на  буффер
    @return Указатель на данные, помещенные в буффер. Если указатель buff не определен,
    возвращается NULL, а в переменную ak_errno помещается код ошибки.                               */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_buffer_get_str( ak_buffer buff )
{
  if( buff == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
   return ak_null_string;
  }
  return (const char *) buff->data;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff Указатель на  буффер
    @return Указатель на данные, помещенные в буффер. Если указатель buff не определен,
    возвращается NULL,  в переменную ak_errno помещается код ошибки.                               */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_buffer_get_ptr( ak_buffer buff )
{
  if( buff == NULL ) {
   ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
   return ak_null_string;
  }
  return buff->data;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff Указатель на  буффер
    @return Размер буффера в байтах. Если указатель buff не определен,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 const size_t ak_buffer_get_size( ak_buffer buff )
{
  if( buff == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a buffer" );
    return ak_error_null_pointer;
  }
  return buff->size;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция сравнивает данные, хранящиеся в буфферах, то есть выполняет
    проверкку равенства left == right.

    @param left Буффер, участвующий в сравнении слева.
    @param right Буффер, участвующий в сравнении справа.
    @return Если данные идентичны, то возвращается \ref ak_true.
    В противном случае, а также в случае возникновения ошибки, возвращается \ref ak_false.
    Код ошибки может быть получен с помощью выщова функции ak_error_get_value().                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_buffer_is_equal( const ak_buffer left, const ak_buffer right )
{
  if( left == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a left buffer" );
    return ak_false;
  }
  if( right == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "use a null pointer to a right buffer" );
    return ak_false;
  }
  if( left->size != right->size ) return ak_false;

 return ak_ptr_is_equal( left->data, right->data, left->size );
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param buff Буффер, для которого производится проверка.

    @return Функция возвращает ak_true, если буффер определен и содержит данные.
    В противном случае, а также в случае возникновения ошибки, возвращается \ref ak_false.
    Код ошибки может быть получен с помощью выщова функции ak_error_get_value().                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_buffer_is_assigned( const ak_buffer buff )
{
  if( buff == NULL ) return ak_false;
  if( buff->data == NULL ) return ak_false;
  if( buff->size == 0 ) return ak_false;

 return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция заполняет буффер случайными данными, выработанными заданным генератором псевдослучайных
    чисел. При этом, новые (случайные) данные не уничтожаются.

    @param buff Буффер, данные которого уничтожаются
    @param generator Генератор псевдо-случайных чисел, используемый для генерации случайного мусора.
    @return Функция возвращает ak_error_ok в случае успешного уничтожения данных. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_buffer_wipe( ak_buffer buff, ak_random generator )
{
  if( buff == NULL ) return ak_error_message( ak_error_null_pointer,
                                                   __func__, "use a null pointer to a buffer" );
 /* мы изменяем только ту память, что нам принадлежит */
  if( buff->flag ) return ak_ptr_wipe( buff->data, buff->size, generator );
   return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция заполняет заданную область памяти случайными данными, выработанными заданным
    генератором псевдослучайных чисел.

    @param ptr Область данных, которая заполняется случайным мусором.
    @param size Размер заполняемой области в байтах.
    @param generator Генератор псевдо-случайных чисел, используемый для генерации случайного мусора.
    @return Функция возвращает ak_error_ok в случае успешного уничтожения данных. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ptr_wipe( ak_pointer ptr, size_t size, ak_random generator )
{
  size_t idx = 0;
  int result = ak_error_ok;

  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer,
                                                __func__, "using null pointer to wipe memory" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length,
                                                  __func__ , "wiping memory with zero length" );
  if( generator == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                   "use a null pointer to a random generator" );

  if( generator->random( generator, ptr, size ) != ak_error_ok ) {
    ak_error_message( ak_error_write_data, __func__, "incorrect memory wiping" );
    memset( ptr, 0, size );
    result = ak_error_write_data;
  }
  /* запись в память при чтении => необходим вызов функции чтения данных из ptr */
  for( idx = 0; idx < size; idx++ ) ((ak_uint8 *)ptr)[idx] += ((ak_uint8 *)ptr)[size - 1 - idx];
  return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает новый буффер заданного размера size и заполняет его псевдо-случайными значениями,
    выработанными с помощью заданного генератора generator.

    @param generator Генератор псевдослучайных чисел, используемый для выработки случайного
    заполнения буффера
    @param size Размер создаваемого буффера в байтах.

    @return Функция возвращает указатель на созданный буффер. В случае возникновения ошибки
    возвращается NULL. Код ошибки может быть получен с помощью вызова ak_error_get_value().        */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_buffer_new_random( ak_random generator, const size_t size )
{
  ak_buffer buff = NULL;
  if( generator == NULL ) { /* использование NULL-генератора */
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to random generator" );
    return NULL;
  }
  if( size <= 0 ) { /* присвоение данных неопределенной длины */
    ak_error_message( ak_error_zero_length, __func__, "using a data with non positive length" );
    return NULL;
  }

  /* создаем буффер */
  if(( buff = ak_buffer_new_size( size )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__, "incorrect memory allocation" );
    return NULL;
  }
  if( generator->random( generator, buff->data, buff->size ) != ak_error_ok ) {
    ak_error_message( ak_error_get_value(), __func__, "incorrect random data generation" );
    return ( buff = ak_buffer_delete( buff ));
  }
 return buff;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                    ak_buffer.c  */
/* ----------------------------------------------------------------------------------------------- */
