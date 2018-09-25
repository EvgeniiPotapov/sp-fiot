/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2017 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
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
/*  ak_compress.c                                                                                  */
/* ----------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_SYSSTAT_H
 #include <sys/stat.h>
#endif
#ifdef LIBAKRYPT_HAVE_FCNTL_H
 #include <fcntl.h>
#endif
#ifdef LIBAKRYPT_HAVE_UNISTD_H
 #include <unistd.h>
#endif
#ifdef LIBAKRYPT_HAVE_ERRNO_H
 #include <errno.h>
#endif

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_compress.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct compress в значения, определяемые
    заданным контекстом функции хеширования.

    @param comp указатель на структуру struct compress
    @param hctx контекст бесключевой функции хеширования
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_create_hash( ak_compress comp, ak_hash hctx )
{
 /* вначале, необходимые проверки */
  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                       "using null pointer to compress context" );
  if( hctx == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                           "using null pointer to hash context" );
  if(( hctx->update == NULL ) || ( hctx->finalize == NULL ) || ( hctx->clean == NULL ))
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                                           "using non initialized hash context" );
 /* теперь собственно инициализация */
  if(( comp->data = (ak_uint8 *) malloc( comp->bsize = hctx->bsize )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                     "wrong memory alllocation for a new temporary data buffer" );
  } else memset( comp->data, 0, hctx->bsize );
  comp->length = 0;

 /* устанавливаем значения и полей и методы из контекста функции хеширования */
  comp->ctx = hctx;
  comp->hsize = hctx->hsize;
  comp->clean = hctx->clean;
  comp->update = hctx->update;
  comp->finalize = hctx->finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция устанавливает значение полей структуры struct compress в значения, определяемые
    заданным контекстом ключевой функции хеширования.

    @param comp указатель на структуру struct compress
    @param mac контекст ключевой функции хеширования
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_create_mac( ak_compress comp, ak_mac mac )
{
 /* вначале, необходимые проверки */
  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                       "using null pointer to compress context" );
  if( mac == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                            "using null pointer to mac context" );
  if(( mac->update == NULL ) || ( mac->finalize == NULL ) || ( mac->clean == NULL ))
    return ak_error_message( ak_error_undefined_function, __func__ ,
                                                            "using non initialized mac context" );
 /* теперь собственно инициализация */
  if(( comp->data = (ak_uint8 *) malloc( comp->bsize = mac->bsize )) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__ ,
                                     "wrong memory alllocation for a new temporary data buffer" );
  } else memset( comp->data, 0, mac->bsize );
  comp->length = 0;

 /* устанавливаем значения и полей и методы из контекста функции хеширования */
  comp->ctx = ( ak_pointer )&mac->choice;
  comp->hsize = mac->hsize;
  comp->clean = mac->clean;
  comp->update = mac->update;
  comp->finalize = mac->finalize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция очищает значения полей структуры struct compress.
    \b Внимание! Удаление и очистка контекста, реализующего вычисления - не производится.

  @param comp указатель на структуру struct compress
  @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
  возвращается ее код.                                                                             */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_destroy( ak_compress comp )
{
  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                    "destroying null pointer to compress context" );
  if( comp->data != NULL ) free( comp->data );

  comp->length =      0;
  comp->ctx =      NULL;
  comp->hsize =       0;
  comp->bsize =       0;
  comp->clean =    NULL;
  comp->update =   NULL;
  comp->finalize = NULL;
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param comp указатель на структуру struct compress.
    @return В случае успеха возвращается ak_error_ok (ноль). В случае возникновения ошибки
    возвращается ее код.                                                                           */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_clean( ak_compress comp )
{
  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using a null pointer to null compress context" );
  if( comp->clean == NULL ) return ak_error_message( ak_error_undefined_function, __func__ ,
                                                             "using an undefined clean function" );
  if( comp->data != NULL ) memset( comp->data, 0, comp->bsize );
  comp->length = 0;
  comp->clean( comp->ctx );
 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param comp указатель на структуру struct compress.
    @param in Сжимаемые данные
    @param size Размер сжимаемых данных в байтах. Данное значение может
    быть произвольным, в том числе равным нулю и/или не кратным длине блока обрабатываемых данных
    @return В случае успеха функция возвращает ноль (\ref ak_error_ok). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_compress_update( ak_compress comp, const ak_pointer in, const size_t size )
{
  ak_uint8 *ptrin = (ak_uint8 *) in;
  size_t quot = 0, offset = 0, newsize = size;

  if( comp == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                 "using a null pointer to null compress context" );
  if( comp->update == NULL ) return ak_error_message( ak_error_undefined_function, __func__ ,
                                                            "using an undefined update function" );

 /* в начале проверяем, есть ли данные во временном буфере */
  if( comp->length != 0 ) {
   /* если новых данных мало, то добавляем во временный буффер и выходим */
    if(( comp->length + newsize ) < comp->bsize ) {
       memcpy( comp->data + comp->length, ptrin, newsize );
       comp->length += newsize;
       return ak_error_ok;
    }
   /* дополняем буффер до длины, кратной bsize */
    offset = comp->bsize - comp->length;
    memcpy( comp->data + comp->length, ptrin, offset );

   /* обновляем значение контекста функции и очищаем временный буффер */
    comp->update( comp->ctx, comp->data, comp->bsize );
    memset( comp->data, 0, comp->bsize );
    comp->length = 0;
    ptrin += offset;
    newsize -= offset;
  }

 /* теперь обрабатываем входные данные с пустым временным буффером */
  if( newsize != 0 ) {
    quot = newsize/comp->bsize;
    offset = quot*comp->bsize;
   /* обрабатываем часть, кратную величине bsize */
    if( quot > 0 ) comp->update( comp->ctx, ptrin, offset );
   /* хвост оставляем на следующий раз */
    if( offset < newsize ) {
      comp->length = newsize - offset;
      memcpy( comp->data, ptrin + offset, comp->length );
    }
  }

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Конечный результат применения сжимающего отображения помещается в область памяти,
    на которую указывает out. Если out равен NULL, то функция создает новый буффер
    (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель на
    буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    Внутренняя структура, хранящая промежуточные данные, не очищается. Это позволят повторно вызывать
    функцию finalize к текущему состоянию.

    @param comp указатель на структуру struct compress.
    @param in Указатель на входные данные для которых вычисляется хеш-код.
    @param size Размер входных данных в байтах.
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_compress_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_compress_finalize( ak_compress comp,
                                            const ak_pointer in, const size_t size, ak_pointer out )
{
  if( comp == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                                  "using a null pointer to null compress context" );
    return NULL;
  }
  if( comp->finalize == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__ ,
                                                           "using an undefined finalize function" );
    return NULL;
  }

 /* начинаем с того, что обрабатываем все переданные данные */
  ak_compress_update( comp, in, size );
 /* потом обрабатываем хвост, оставшийся во временном буффере, и выходим */
 return comp->finalize( comp->ctx, comp->data, comp->length, out );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция вычисляет результат сжимающего отображения для заданного файла и помещает
    его в область памяти, на которую указывает out. Если out равен NULL, то функция создает новый
    буффер (структуру struct buffer), помещает в нее вычисленное значение и возвращает на указатель
    на буффер. Буффер должен позднее быть удален с помощью вызова ak_buffer_delete().

    @param comp указатель на структуру struct compress.
    @param filename имя сжимаемого файла
    @param out Область памяти, куда будет помещен результат. Память должна быть заранее выделена.
    Размер выделяемой памяти может быть определен с помощью вызова ak_compress_get_code_size().
    Указатель out может принимать значение NULL.

    @return Функция возвращает NULL, если указатель out не есть NULL, в противном случае
    возвращается указатель на буффер, содержащий результат вычислений. В случае возникновения
    ошибки возвращается NULL, при этом код ошибки может быть получен с помощью вызова функции
    ak_error_get_value().                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 ak_buffer ak_compress_file( ak_compress comp, const char* filename, ak_pointer out )
{
  int fd = 0;
  struct stat st;
  size_t len = 0;
  ak_uint8 *localbuffer; /* место для локального считывания информации */
  size_t block_size = 4096; /* оптимальная длина блока для Windows пока не ясна */
  ak_buffer result = NULL;

 /* выполняем необходимые проверки */
  if( comp == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to compress context" );
    return NULL;
  }
  if( filename == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__ , "use a null pointer to filename" );
    return NULL;
  }

  if(( fd = open( filename, O_RDONLY | O_BINARY )) < 0 ) {
    ak_error_message( ak_error_open_file, __func__, strerror( errno ));
    return NULL;
  }
  if( fstat( fd, &st ) ) {
    close( fd );
    ak_error_message( ak_error_access_file,  __func__, strerror( errno ));
    return NULL;
  }

 /* для файла нулевой длины результатом будет хеш от нулевого вектора */
  ak_compress_clean( comp );
  if( !st.st_size ) return ak_compress_finalize( comp, "", 0, out );

 /* готовим область для хранения данных */
  #ifdef _WIN32
    block_size = ak_max( 4096, comp->bsize );
  #else
    block_size = ak_max( st.st_blksize, comp->bsize );
  #endif
 /* здесь мы выделяем локальный буффер для считывания/обработки данных */
  if((localbuffer = ( ak_uint8 * ) malloc( block_size )) == NULL ) {
    close( fd );
    ak_error_message( ak_error_out_of_memory, __func__ , "out of memory" );
    return NULL;
  }
 /* теперь обрабатываем файл с данными */
 #ifdef _WIN32
  read_label: len = read( fd, localbuffer, (unsigned int) block_size );
 #else
  read_label: len = read( fd, localbuffer, block_size );
 #endif
  if( len == block_size ) {
    ak_compress_update( comp, localbuffer, block_size ); /* добавляем считанные данные */
    goto read_label;
  } else {
           size_t qcnt = len / comp->bsize,
                  tail = len - qcnt*comp->bsize;
           if( qcnt ) ak_compress_update( comp, localbuffer, qcnt*comp->bsize );
           result = ak_compress_finalize( comp, localbuffer + qcnt*comp->bsize, tail, out );
         }
 /* очищаем за собой данные, содержащиеся в контексте */
  ak_compress_clean( comp );
 /* закрываем данные */
  close(fd);
  free( localbuffer );
 return result;
}

/*! -----------------------------------------------------------------------------------------------
    \example example-internal-compress01.c

 * ----------------------------------------------------------------------------------------------- */
/*                                                                                   ak_compress.c */
/* ----------------------------------------------------------------------------------------------- */
