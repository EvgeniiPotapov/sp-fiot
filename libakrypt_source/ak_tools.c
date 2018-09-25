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
/*   ak_tools.c                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_tools.h>
 #include <ak_buffer.h>
 #include <errno.h>

#ifdef LIBAKRYPT_HAVE_TERMIOS_H
 #include <termios.h>
#endif
#ifdef LIBAKRYPT_HAVE_FCNTL_H
  #include <fcntl.h>
#endif
#ifdef LIBAKRYPT_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает область памяти, на которую указывает указатель ptr, как массив
    последовательно записанных байт фиксированной длины, создает в оперативной памяти строку и
    последовательно выводит в нее значения, хранящиеся в заданной области памяти.
    Значения выводятся в шестнадцатеричной системе счисления.

    Пример использования.
  \code
    ak_uint8 data[5] = { 1, 2, 3, 4, 5 };
    ak_uint8 *str = ak_ptr_to_hexstr( data, 5, ak_false );
    printf("%s\n", str );
    free(str);
  \endcode

    @param ptr Указатель на область памяти
    @param ptr_size Размер области памяти (в байтах)
    @param reverse Последовательность вывода байт в строку. Если reverse равно \ref ak_false,
    то байты выводятся начиная с младшего к старшему.  Если reverse равно \ref ak_true, то байты
    выводятся начиная от старшего к младшему (такой способ вывода принят при стандартном выводе
    чисел: сначала старшие разряды, потом младшие).

    @return Функция возвращает указатель на созданную строку, которая должна быть позднее удалена
    пользователем с помощью вызова функции free(). В случае ошибки конвертации возвращается NULL.
    Код ошибки может быть получен с помощью вызова функции ak_error_get_code()                     */
/* ----------------------------------------------------------------------------------------------- */
 char *ak_ptr_to_hexstr( const ak_pointer ptr, const size_t ptr_size, const ak_bool reverse )
{
  char *nullstr = NULL;
  size_t len = 1 + (ptr_size << 1);

  if( ptr == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "using null pointer to data" );
    return NULL;
  }
  if( ptr_size <= 0 ) {
    ak_error_message( ak_error_zero_length, __func__ , "using data with zero or negative length" );
    return NULL;
  }

  if(( nullstr = (char *) malloc( len )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ , "incorrect memory allocation" );
  }
    else {
      size_t idx = 0, js = 0, start = 0, offset = 2;
      ak_uint8 *data = ( ak_uint8 * ) ptr;

      memset( nullstr, 0, len );
      if( reverse ) { // движение в обратную сторону - от старшего байта к младшему
        start = len-3; offset = -2;
      }
      for( idx = 0, js = start; idx < ptr_size; idx++, js += offset ) {
        char str[4];
        ak_snprintf( str, 3, "%02X", data[idx] );
        memcpy( nullstr+js, str, 2 );
      }
    }
 return nullstr;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция рассматривает область памяти, на которую указывает указатель ptr, как массив
    последовательно записанных байт фиксированной длины.
    Символьная (шестнадцатеричная) форма записи массива ptr помещается в заранее выделенный массив out.
    Если длины недостаточно, то возбуждается ошибка.

    Пример использования.
  \code
    ak_uint8 data[5] = { 1, 2, 3, 4, 5 };
    ak_uint8 data_out[12];

    if( ak_ptr_to_hexstr_static( data, 5, data_out, 12, ak_false ) == ak_error_ok )
      printf("%s\n", data_out );
  \endcode

    @param ptr Указатель на область памяти
    @param ptr_size Размер области памяти (в байтах)
    @param out Указатель на область памяти, в которую записывается символьное представление данных
    @param out_size Размер области памяти (в байтах); должен быть не менее, чем
    величина 1 + 2*`ptr_size`.

    @param reverse Последовательность вывода байт в строку. Если reverse равно \ref ak_false,
    то байты выводятся начиная с младшего к старшему.  Если reverse равно \ref ak_true, то байты
    выводятся начиная от старшего к младшему (такой способ вывода принят при стандартном выводе
    чисел: сначала старшие разряды, потом младшие).

    @return Если преобразование прошло успешно, возвращается \ref ak_error_ok. В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_ptr_to_hexstr_static( const ak_pointer ptr, const size_t ptr_size,
                                     ak_pointer out, const size_t out_size, const ak_bool reverse )
{
  ak_uint8 *data = ( ak_uint8 * ) ptr;
  size_t len = 1 + (ptr_size << 1);
  size_t idx = 0, js = 0, start = 0, offset = 2;

  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                     "using null pointer to data" );
  if( ptr_size <= 0 ) return ak_error_message( ak_error_zero_length, __func__ ,
                                                        "using data with zero or negative length" );
  if( out_size < len ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                                 "using small size output buffer" );
  memset( out, 0, len );
  if( reverse ) { // движение в обратную сторону - от старшего байта к младшему
    start = len-3; offset = -2;
  }
  for( idx = 0, js = start; idx < ptr_size; idx++, js += offset ) {
     char str[4];
     ak_snprintf( str, 3, "%02X", data[idx] );
     memcpy( (ak_uint8 *)out+js, str, 2 );
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Конвертация символа в целочисленное значение                                            */
/* ----------------------------------------------------------------------------------------------- */
 inline static ak_uint32 ak_xconvert( const char c )
{
    switch( c )
   {
      case 'a' :
      case 'A' : return 10;
      case 'b' :
      case 'B' : return 11;
      case 'c' :
      case 'C' : return 12;
      case 'd' :
      case 'D' : return 13;
      case 'e' :
      case 'E' : return 14;
      case 'f' :
      case 'F' : return 15;
      case '0' : return 0;
      case '1' : return 1;
      case '2' : return 2;
      case '3' : return 3;
      case '4' : return 4;
      case '5' : return 5;
      case '6' : return 6;
      case '7' : return 7;
      case '8' : return 8;
      case '9' : return 9;
      default : ak_error_set_value( ak_error_undefined_value ); return 0;
 }
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция преобразует строку символов, содержащую последовательность шестнадцатеричных цифр,
    в массив данных.

    @param hexstr Строка символов.
    @param ptr Указатель на область памяти (массив), в которую будут размещаться данные.
    @param size Максимальный размер памяти (в байтах), которая может быть помещена в массив.
    Если исходная строка требует больший размер, то возбуждается ошибка.
    @param reverse Последовательность считывания байт в память. Если reverse равно \ref ak_false
    то первые байты строки (с младшими индексами) помещаются в младшие адреса, а старшие байты -
    в старшие адреса памяти. Если reverse равно \ref ak_true, то производится разворот,
    то есть обратное преобразование при котором элементы строки со старшиси номерами помещаются
    в младшие разряды памяти (такое представление используется при считывании больших целых чисел).

    @return В случае успеха возвращается ноль. В противном случае, в частности,
                      когда длина строки превышает размер массива, возвращается код ошибки.        */
/* ----------------------------------------------------------------------------------------------- */
 int ak_hexstr_to_ptr( const char *hexstr, ak_pointer ptr, const size_t size, const ak_bool reverse )
{
  int i = 0;
  ak_uint8 *bdata = ptr;
  size_t len = 0;

  if( hexstr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                             "using null pointer to a hex string" );
  if( ptr == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                                 "using null pointer to a buffer" );
  if( size == 0 ) return ak_error_message( ak_error_zero_length, __func__,
                                                          "using zero value for length of buffer" );
  len = strlen( hexstr );
  if( len&1 ) len++;
  len >>= 1;
  if( size < len ) return ak_error_message( ak_error_wrong_length, __func__ ,
                                                               "using a buffer with small length" );

  memset( ptr, 0, size ); // перед конвертацией мы обнуляем исходные данные
  ak_error_set_value( ak_error_ok );
  if( reverse ) {
    for( i = strlen( hexstr )-2, len = 0; i >= 0 ; i -= 2, len++ ) {
       bdata[len] = (ak_xconvert( hexstr[i] ) << 4) + ak_xconvert( hexstr[i+1] );
    }
    if( i == -1 ) bdata[len] = ak_xconvert( hexstr[0] );
  } else {
        for( i = 0, len = 0; i < (int) strlen( hexstr ); i += 2, len++ ) {
           bdata[len] = (ak_xconvert( hexstr[i] ) << 4);
           if( i < (int) strlen( hexstr )-1 ) bdata[len] += ak_xconvert( hexstr[i+1] );
        }
    }
 return ak_error_get_value();
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция сравнивает две области памяти одного размера, на которые указывают аргументы функции.
    Пример использования функции (результат выполнения функции должен быть \ref ak_false).
  \code
    ak_uint8 data_left[5] = { 1, 2, 3, 4, 5 };
    ak_uint8 data_right[5] = { 1, 2, 3, 4, 6 };

    if( ak_ptr_is_equal( data_left, data_right, 5 )) printf("Is equal");
     else printf("Not equal");
  \endcode

    @param left Указатель на область памяти, участвующей в сравнении слева.
    @param right Указатель на область пямяти, участвующей в сравнении справа.
    @param size Размер области, для которой производяится сравнение.
    @return Если данные идентичны, то возвращается \ref ak_true.
    В противном случае, а также в случае возникновения ошибки, возвращается \ref ak_false.
    Код шибки может быть получен с помощью выщова функции ak_error_get_value().                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_bool ak_ptr_is_equal( const ak_pointer left, const ak_pointer right, const size_t size )
{
  size_t i = 0;
  ak_bool result = ak_true;
  ak_uint8 *lp = left, *rp = right;

  if(( left == NULL ) || ( right == NULL )) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer" );
    return ak_false;
  }

  for( i = 0; i < size; i++ )
     if( lp[i] != rp[i] ) result = ak_false;

  return result;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция принимает два параметра:
    @param pass Строка, в которую будет помещен пароль. Память под данную строку должна быть
    выделена заранее. Если в данной памяти хранились какие-либо данные, то они будут уничтожены.
    @param psize Максимально возможная длина пароля. Предполагается, что именно
    это значение задает размер области памяти, на которую указывает pass.

    Отметим, что в случае ввода пароля нулевой длины функция возвращает ошибку с кодом
    \ref ak_error_terminal

    @return В случае успеха функция возвращает значение \ref ak_error_ok. В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_password_read( char *pass, const size_t psize )
{
   size_t len = 0;
   int error = ak_error_ok;

 #ifndef LIBAKRYPT_HAVE_TERMIOS_H
  #ifdef _WIN32
   char c = 0;
   DWORD mode, count;
   HANDLE ih = GetStdHandle( STD_INPUT_HANDLE  );
   if( !GetConsoleMode( ih, &mode ))
     return ak_error_message( ak_error_terminal, __func__, "not connected to a console" );
   SetConsoleMode( ih, mode & ~( ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT ));

   memset( pass, 0, psize );
   while( ReadConsoleA( ih, &c, 1, &count, NULL) && (c != '\r') && (c != '\n') && (len < psize-1) ) {
     pass[len]=c;
     len++;
   }
   pass[len]=0;

   /* восстанавливаем настройки консоли */
   SetConsoleMode( ih, mode );
   if(( len = strlen( pass )) < 1 )
     return ak_error_message( ak_error_zero_length, __func__ , "input a very short password");
   return error;

  #endif
   return ak_error_undefined_function;

 #else
  /* обрабатываем терминал */
   struct termios ts, ots;

   tcgetattr( STDIN_FILENO, &ts);   /* получаем настройки терминала */
   ots = ts;
   ts.c_cc[ VTIME ] = 0;
   ts.c_cc[ VMIN  ] = 1;
   ts.c_iflag &= ~( BRKINT | INLCR | ISTRIP | IXOFF ); // ICRNL | IUTF8
   ts.c_iflag |=    IGNBRK;
   ts.c_oflag &= ~( OPOST );
   ts.c_cflag &= ~( CSIZE | PARENB);
   ts.c_cflag |=    CS8;
   ts.c_lflag &= ~( ECHO | ICANON | IEXTEN | ISIG );
   tcsetattr( STDIN_FILENO, TCSAFLUSH, &ts );
   tcgetattr( STDIN_FILENO, &ts ); /* проверяем, что все установилось */
   if( ts.c_lflag & ECHO ) {
        ak_error_message( error = ak_error_terminal, __func__, "failed to turn off echo" );
        goto lab_exit;
   }

   memset( pass, 0, psize );
   fgets( pass, psize, stdin );
   if(( len = strlen( pass )) < 2 )
     ak_error_message( error = ak_error_zero_length, __func__ , "input a very short password");
   if( len > 0 ) pass[len-1] = 0;
    else pass[0] = 0;

  /* убираем за собой и восстанавливаем настройки */
   lab_exit: tcsetattr( STDIN_FILENO, TCSANOW, &ots );
   return error;
 #endif

 /* некорректный путь компиляции исходного текста функции */
 return ak_error_undefined_function;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param password Буфер, в который помещается пароль. Буфер должен быть создан заранее с заданным
    размером хранящихся в нем данных (с помощью вызова функции ak_buffer_new_size() )
    Если в буффере хранились данные, то они будут уничтожены.

    Отметим, что в случае ввода пароля нулевой длины функция возвращает ошибку с кодом
    \ref ak_error_terminal

    @return В случае успеха функция возвращает значение \ref ak_error_ok. В случае возникновения
    ошибки возвращается ее код.                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 int ak_password_read_buffer( ak_buffer password )
{
  int error = ak_error_ok;
  if( password == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                       "using null pointer to password buffer" );
 /* если нужно создаем буффер достаточно большого размера */
  if((password->data == NULL ) || (password->size == 0 )) {
    if(( error = ak_buffer_create_size( password, 256 )) != ak_error_ok )
      return ak_error_message( error, __func__, "incorrect creation of fixed size buffer");
  }
 /* считываем пароль */
  if(( error = ak_password_read( password->data, password->size )) != ak_error_ok ) {
    return ak_error_message( error, __func__, "invalind password reading from standard console");
  }
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_tools.c  */
/* ----------------------------------------------------------------------------------------------- */
