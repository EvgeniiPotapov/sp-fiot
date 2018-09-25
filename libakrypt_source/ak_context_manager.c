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
/*   ak_context_manager.c                                                                          */
/* ----------------------------------------------------------------------------------------------- */
 #include <ak_oid.h>
 #include <ak_tools.h>
 #include <ak_context_manager.h>

/* ----------------------------------------------------------------------------------------------- */
/*                                 класс ak_context_manager_node                                   */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция создает новый элемент структуры управления контекстами, заполняя его поля значениями,
    передаваемыми в качестве аргументов функции.

    @param ctx Контекст, который будет храниться в структуре управленияя контекстами
    @param id Идентификатор контекста, величина по которой пользовать может получить доступ
    к функциям, реализующим действия с контекстом.
    @param engine тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @param description пользовательское описание контекста
    @param func функция освобождения памяти, занимаемой контекстом
    @return Функция возвращает указатель на созданный элемент структуры управления контекстами.
    В случае возникновения ошибки возвращается NULL. Код ошибки может быть получен с помощью
    вызова функции ak_error_get_value().                                                           */
/* ----------------------------------------------------------------------------------------------- */
 ak_context_node ak_context_node_new( ak_pointer ctx, ak_handle id, ak_oid_engine engine,
                                            const char *description, ak_function_free_object *func )
{
  int error = ak_error_ok;
  ak_context_node node = NULL;

 /* минимальные проверки */
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to context" );
    return NULL;
  }
 /* для добавления ссылок на константы, нам пришлось убрать эту проверку
  if( func == NULL ) {
    ak_error_message( ak_error_undefined_function, __func__,
                                         "using a null pointer to context free function" );
    return NULL;
  }
 */
 /* создаем контекст */
  if(( node = malloc( sizeof( struct context_node ))) == NULL ) {
    ak_error_message( ak_error_out_of_memory, __func__,
                                  "wrong memory allocation for new context manager node" );
    return NULL;
  }

 /* инициализируем буффер и присваиваем ему значение */
  if(( error = ak_buffer_create( &node->description )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong creation of internal buffer" );
    return ( node = ak_context_node_delete( node ));
  }

  if(( error = ak_buffer_set_str( &node->description, description )) != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong initialization of internal buffer" );
    return ( node = ak_context_node_delete( node ));
  }

 /* присваиваем остальные данные */
  node->ctx = ctx;
  node->id = id;
  node->engine = engine;
  node->free = func;
  node->status = node_is_equal;

 return node;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @param pointer указатель на элемент структуры управления контекстами.
    @return Функция всегда возвращает NULL.                                                        */
/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_context_node_delete( ak_pointer pointer )
{
  ak_context_node node = ( ak_context_node ) pointer;

  if( node == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__,
                                       "wrong deleting a null pointer to context manager node" );
    return NULL;
  }

  ak_buffer_destroy( &node->description );

  if( node->free != NULL ) {
    if( node->ctx != NULL ) node->ctx = node->free( node->ctx );
    node->free = NULL;
  }
  node->id = ak_error_wrong_handle;
  node->status = node_undefined;
  node->engine = undefined_engine;
  free( node );

 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Мьютекс для блокировки структуры управления контекстами */
 static pthread_mutex_t ak_context_manager_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ----------------------------------------------------------------------------------------------- */
/*                                    класс ak_context_manager                                     */
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует структуру управления контекстами, присваивая ее полям значения,
    необходимые для обеспечения корректной работы.
    Начальное значение ожидаемого структурой количества контекстов, с которыми будет произодится
    работа, является внешним параметром библиотеки. Данное значение устанавливается
    в файле `libakrypt.conf` (см. раздел \ref construction_options).

    @param manager Указатель на структуру управления ключами
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_create( ak_context_manager manager )
{
  size_t idx = 0;
  int error = ak_error_ok;

  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                            "using a null pointer to context manager structure" );
 /* инициализируем генератор ключей */
#if defined(__unix__) || defined(__APPLE__)
  if(( error = ak_random_create_file( &manager->key_generator, "/dev/urandom" )) != ak_error_ok )
    return ak_error_message( error, __func__,
                             "wrong initialization of /dev/random for random number generation" );
#else
 #ifdef _WIN32
   if(( error = ak_random_create_winrtl( &manager->key_generator )) != ak_error_ok ) {
     ak_error_message( error, __func__,
                         "wrong initialization a random generator from default crypto provider" );
     ak_error_message( ak_error_ok, __func__, "trying to use lcg generator" );
     if(( error = ak_random_create_lcg( &manager->key_generator )) != ak_error_ok )
       return ak_error_message( error, __func__,
                                "wrong initialization of all types of random generators" );
   }
 #else
   #error ak_context_manager_create(): using a non defined path of compilation
 #endif
#endif

 /* инициализируем указатели контекстов */
  manager->size = ak_libakrypt_get_option("context_manager_size"); //ak_libakrypt_get_context_manager_size();

  if(( manager->array = malloc( manager->size*sizeof( ak_pointer ))) == NULL ) {
    ak_context_manager_destroy( manager );
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                            "wrong memory allocation for context manager nodes" );
  }
  for( idx = 0; idx < manager->size; idx++ ) manager->array[idx] = NULL;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция выделяет дополнительную память под массив хранения контекстов.
    При выделении памяти производится перенос содержащихся в массиве указателей
    (элементов структуры управления контекстами) в новую область памяти.
    Старая область памяти уничтожается.

    При выделении памяти размер новой области увеличивается в два раза, по сравнению с предыдущим
    объемом, то есть происходит двукратное увеличение. Максимальное число
    хранимых в структуре управления контекстов является внешним параметром библиотеки.
    Данное значение устанавливается в файле `libakrypt.conf` (см. раздел \ref construction_options).

    @param manager Указатель на структуру управления ключами
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_morealloc( ak_context_manager manager )
{
  ak_context_node *newarray = NULL;
  size_t idx = 0, newsize = (manager->size << 1);
  int msize = ak_libakrypt_get_option("context_manager_max_size");

  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                            "using a null pointer to context manager structure" );
  if( newsize <= manager->size )
    return ak_error_message( ak_error_context_manager_size, __func__ ,
                                      "unexpected value of new value of context manager's size" );
  if(( msize < 0 ) || (( int )newsize > msize ))
    return ak_error_message( ak_error_context_manager_max_size, __func__,
                                   "current size of context manager exceeds permissible bounds" );
/* это отладочный вывод, который сообщает о выделении новой памяти
   ak_error_message( ak_error_ok, __func__ ,
                         "TODO: load maximum of manager->size value from /etc/libakrypt.conf"); */

  if(( newarray = malloc( newsize*sizeof( ak_pointer ))) == NULL )
    return ak_error_message( ak_error_out_of_memory, __func__ ,
                                              "wrong memory allocation for context manager nodes" );
 /* копируем данные и очищаем память */
  for( idx = 0; idx < manager->size; idx++ ) {
     newarray[idx] = manager->array[idx];
     manager->array[idx] = NULL;
   }
  for( idx = manager->size; idx < newsize; idx++ ) newarray[idx] = NULL;

  free( manager->array );
  manager->array = newarray;
  manager->size = newsize;

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция удаляет структуру управления контекстами, уничтожая данные, которыми она владеет.
    При выполнении функции:
    - уничтожаются контексты, хранящиеся в структуре,
    - уничтожается генератор псевдо-случайных чисел, использовавшийся для генерации
      ключевой информации.

    @param manager Указатель на структуру управления ключами
    @return В случае успеха функция возвращает \ref ak_error_ok (ноль). В противном случае
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_destroy( ak_context_manager manager )
{
  size_t idx = 0;
  int error = ak_error_ok;

  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                            "using a null pointer to context manager structure" );
  if( manager->array == NULL ) {
    ak_error_message( error = ak_error_undefined_value, __func__ ,
                                                   "cleaning context manager with empty memory" );
  } else {
          /* удаляем ключевые структуры */
           for( idx = 0; idx < manager->size; idx++ )
              if( manager->array[idx] != NULL )
                manager->array[idx] = ak_context_node_delete( manager->array[idx] );

           /* очищаем и уничтожаем память */
           memset( manager->array, 0, manager->size);
           free( manager->array );
           manager->array = NULL;
  }
  manager->size = 0;

 /* удаляем генератор ключей */
  if(( error = ak_random_destroy( &manager->key_generator )) != ak_error_ok )
    return ak_error_message( error, __func__ , "using a null pointer to random key generator" );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! По заданному значению индекса массива idx функция вычисляет значение дескриптора,
    доступного пользователю. Обратное преобразование задается функцией
    ak_context_manager_handle_to_idx().

    @param manager Указатель на структуру управления контекстами
    @param idx Индекс контекста в массиве
    @return Функция возвращает значение дескриптора контекста.                                     */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_context_manager_idx_to_handle( ak_context_manager manager, size_t idx )
{
  return idx;
}

/* ----------------------------------------------------------------------------------------------- */
/*! По заданному значению дескриптора контекста handle функция вычисляет значение
    индекса массива, по адресу которого располагается контекст.
    Обратное преобразование задается функцией ak_context_manager_idx_to_handle().

    @param manager Указатель на структуру управления контекстами
    @param handle Дескриптор контектса
    @return Функция возвращает значение дескриптора контекста.                                     */
/* ----------------------------------------------------------------------------------------------- */
 size_t ak_context_manager_handle_to_idx( ak_context_manager manager, ak_handle handle )
{
  return ( size_t )handle;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция находит первый равный NULL адрес элемента структуры и
    помещает по этому адресу новый элемент. В случае, если текущей объем памяти недостаточен для
    размещения нового элемента, происходит выделение нового фрагмента памяти.

    @param manager Указатель на структуру управления контекстами
    @param ctx Контекст, который будет храниться в структуре управленияя контекстами
    @param engine тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @param description пользовательское описание контекста
    @param func функция освобождения памяти, занимаемой контекстом
    @return Функция возвращает дескриптор созданного контекста. В случае
    возникновения ошибки возвращается значение \ref ak_error_wrong_handle. Код ошибки может быть
    получен с помощью вызова функции ak_error_get_value().                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_context_manager_add_node( ak_context_manager manager, ak_pointer ctx,
                     ak_oid_engine engine, const char *description, ak_function_free_object *func )
{
  size_t idx = 0;
  int error = ak_error_ok;
  ak_context_node node = NULL;
  ak_handle handle = ak_error_wrong_handle;

 /* минимальные проверки */
  if( manager == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to context manager" );
    return ak_error_wrong_handle;
  }
  if( ctx == NULL ) {
    ak_error_message( ak_error_null_pointer, __func__, "using a null pointer to context" );
    return ak_error_wrong_handle;
  }
  if( description == NULL )  {
    ak_error_message( ak_error_null_pointer, __func__,
                                                    "using a null pointer to description string" );
    return ak_error_wrong_handle;
  }

 /* блокируем доступ к структуре управления контекстами */
  pthread_mutex_lock( &ak_context_manager_mutex );

 /* ищем свободный адрес */
  for( idx = 0; idx < manager->size; idx++ ) {
     if( manager->array[idx] == NULL ) break;
  }
  if( idx == manager->size ) {
    if(( error =  ak_context_manager_morealloc( manager )) != ak_error_ok ) {
      ak_error_message( error, __func__, "wrong allocation a new memory for context manager" );
      pthread_mutex_unlock( &ak_context_manager_mutex );
      return ak_error_wrong_handle;
    }
  }

 /* адрес найден, теперь размещаем контекст */
  handle = ak_context_manager_idx_to_handle( manager, idx );
  if(( node = ak_context_node_new( ctx, handle, engine, description, func )) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__, "wrong creation of context manager node" );
    pthread_mutex_unlock( &ak_context_manager_mutex );
    return ak_error_wrong_handle;
  }
  manager->array[idx] = node;
  pthread_mutex_unlock( &ak_context_manager_mutex );

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_delete_node( ak_context_manager manager, ak_handle handle )
{
  size_t idx = 0;

  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using a null pointer to context manager" );
 /* получаем индекс из значения дескриптора */
  idx = ak_context_manager_handle_to_idx( manager, handle );
  if( idx >= manager->size ) return ak_error_message( ak_error_wrong_handle, __func__,
                                                          "using an unexpected value of handle" );
 /* блокируем доступ и удаляем объект */
  pthread_mutex_lock( &ak_context_manager_mutex );
  manager->array[idx] = ak_context_node_delete( manager->array[idx] );
  pthread_mutex_unlock( &ak_context_manager_mutex );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция проверяет, что внутренний массив контекстов содержит в себе отличный от NULL контекст
    с заданным значеним дескриптора ключа. Функция не экспортируется.

    @param manager Контекст структуры управления контекстами.
    @param handle Дескриптор контекста.
    @param idx Указатель на индекс контекста в массиве контекстов.
    @return В случае ошибки возвращается ее код. В случае успеха, возвращается значение
    \ref ak_error_ok                                                                               */
/* ----------------------------------------------------------------------------------------------- */
 int ak_context_manager_handle_check( ak_context_manager manager, ak_handle handle, size_t *idx )
{
 /* проверяем менеджер контекстов */
  if( manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__,
                                                      "using null pointer to context manager" );
 /* проверяем, что значение handle определено */
  if( handle == ak_error_wrong_handle ) return ak_error_message( ak_error_wrong_handle,
                                                  __func__, "using an undefined handle value" );
 /* определяем индекс */
  *idx = ak_context_manager_handle_to_idx( manager, handle );

 /* проверяем границы */
  if( *idx >= manager->size )
    return ak_error_message( ak_error_wrong_handle, __func__, "invalid handle index" );

 /* проверяем наличие node */
  if( manager->array[*idx] == NULL )
    return ak_error_message( ak_error_null_pointer, __func__,
                                               "using a null pointer to context manager node" );
 /* проверяем наличие контекста */
  if( manager->array[*idx]->ctx == NULL )
    return ak_error_message( ak_error_null_pointer, __func__, "using null pointer to context" );

 return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                 теперь глобальный ak_context_manager                            */
/* ----------------------------------------------------------------------------------------------- */
 static ak_context_manager libakrypt_manager = NULL;

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_create_context_manager( void )
{
  int error = ak_error_ok;

 /* блокируем доступ */
  pthread_mutex_lock( &ak_context_manager_mutex );

  if(( libakrypt_manager = malloc( sizeof( struct context_manager ))) == NULL )
    ak_error_message( error = ak_error_out_of_memory, __func__, "wrong memory allocation" );
  else {
         if(( error = ak_context_manager_create( libakrypt_manager )) != ak_error_ok )
           ak_error_message( error, __func__, "incorrect initialization of context manager" );
       }

  pthread_mutex_unlock( &ak_context_manager_mutex );
 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 int ak_libakrypt_destroy_context_manager( void )
{
  int error = ak_error_ok;

  if( libakrypt_manager == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                 "destroying a null pointer to context manager" );

  pthread_mutex_lock( &ak_context_manager_mutex );
  if(( error = ak_context_manager_destroy( libakrypt_manager )) != ak_error_ok )
    ak_error_message( error, __func__, "wrong destroing of context manager" );

  free( libakrypt_manager );
  pthread_mutex_unlock( &ak_context_manager_mutex );

 return error;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_context_manager ak_libakrypt_get_context_manager( void )
{
  if( libakrypt_manager != NULL ) return libakrypt_manager;

  ak_error_message( ak_error_null_pointer, __func__, "using null pointer to context manager" );
 return NULL;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Для существующего контекста, под который ранее выделена память с помощью вызова malloc(),
    функция создает его дескриптор, и размещает контекст в глобальной структуре управления контекстами.
    Данная функция используется производящими функциями пользовательского интерфейса.

    @param ctx контекст функции бесключевого хеширования
    (контекст не должен быть указателем на статическую переменную).
    @param engine тип контекста: блочный шифр, функия хеширования, массив с данными и т.п.
    @param description пользовательское описание контекста
    @param delete_function функция освобождения памяти, занимаемой контекстом
    @return Функция возвращает дескриптор созданного контекста. В случае
    возникновения ошибки возвращается значение \ref ak_error_wrong_handle. Код ошибки может быть
    получен с помощью вызова функции ak_error_get_value().                                         */
/* ----------------------------------------------------------------------------------------------- */
 ak_handle ak_libakrypt_new_handle( ak_pointer ctx,
          ak_oid_engine engine, const char *description, ak_function_free_object *delete_function )
{
  ak_context_manager manager = NULL;
  ak_handle handle = ak_error_wrong_handle;

 /* получаем доступ к структуре управления контекстами */
  if(( manager = ak_libakrypt_get_context_manager()) == NULL ) {
    ak_error_message( ak_error_get_value(), __func__ , "using a non initialized context manager" );
    ctx = delete_function( ctx );
    return ak_error_wrong_handle;
  }

 /* создаем элемент структуры управления контекстами */
  if(( handle = ak_context_manager_add_node(
           manager, ctx, engine, description, delete_function )) == ak_error_wrong_handle ) {
    ak_error_message( ak_error_get_value(), __func__ , "wrong creation of context manager node" );
    ctx = delete_function( ctx );
    return ak_error_wrong_handle;
  }

 return handle;
}

/* ----------------------------------------------------------------------------------------------- */
 ak_pointer ak_handle_get_context( ak_handle handle , ak_oid_engine engine )
{
  size_t idx = 0;
  int error = ak_context_manager_handle_check( libakrypt_manager, handle, &idx );

  if( error != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong handle" );
    return NULL;
  }

  if( libakrypt_manager->array[idx]->engine != engine ) {
    ak_error_message( ak_error_oid_engine, __func__, "using wrong engine for given handle" );
    return NULL;
  }

 return libakrypt_manager->array[idx]->ctx;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return В случае успеха функция возвращает тип криптографического механизма. В противном случае,
   возвращается значение \ref undefined_engine. Код ошибки может быть получен с помощью вызова
   функции ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 ak_oid_engine ak_handle_get_engine( ak_handle handle )
{
  size_t idx = 0;
  int error = ak_context_manager_handle_check( libakrypt_manager, handle, &idx );

  if( error == ak_error_ok ) return libakrypt_manager->array[idx]->engine;

  ak_error_message( error, __func__, "wrong handle" );
 return undefined_engine;
}

/* ----------------------------------------------------------------------------------------------- */
/*! @return В случае успеха функция возвращает строку символов, содержащую символьное описание
   типа криптографического механизма. В противном случае,
   возвращается значение \ref ak_null_string. Код ошибки может быть получен с помощью вызова
   функции ak_error_get_value()                                                                    */
/* ----------------------------------------------------------------------------------------------- */
 const char *ak_handle_get_engine_str( ak_handle handle )
{
  size_t idx = 0;
  int error = ak_context_manager_handle_check( libakrypt_manager, handle, &idx );

  if( error != ak_error_ok ) {
    ak_error_message( error, __func__, "wrong handle" );
    return ak_null_string;
  }

 return ak_libakrypt_get_engine_str( libakrypt_manager->array[idx]->engine );
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция уничтожает дескриптор, а также контекст объекта,
   связанного с данным дескриптором.

    @param handle Дескриптор уничтожаемого объекта.
    @return В случае успеха функция возвращает \ref ak_error_ok. В противном случае,
    возвращается код ошибки.                                                                       */
/* ----------------------------------------------------------------------------------------------- */
 int ak_handle_delete( ak_handle handle )
{
  return ak_context_manager_delete_node( libakrypt_manager, handle );
}

/* ----------------------------------------------------------------------------------------------- */
/*! \example example-context-manager-node.c                                                        */
/*! \example example-context-manager.c                                                             */
/* ----------------------------------------------------------------------------------------------- */
/*                                                                           ak_context_manager.c  */
/* ----------------------------------------------------------------------------------------------- */
