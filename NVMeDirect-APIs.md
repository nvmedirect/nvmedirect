# NVMeDirect APIs

## Adminstration and setup

### NVMED* nvmed_open (char* PATH, int flags);
* Open the specified NVMe device.
* Argument
    * PATH : Path to the NVMe device (e.g., /dev/nvmed0n1)
    * flags :
        * NVMED_NO_CACHE - Do not use the block cache in the NVMeDirect framework.
* Return Value
    * On success, nvmed_open() returns a pointer to the struct NVMED
    * On error, NULL is returned

### int nvmed_close (NVMED* nvmed);
* Close the NVMe device
* Argument
    * nvmed : pointer to the struct NVMED
* Return Value
    * On success, nvmed_close() returns 0
    * On error, -1 (NVMED_FAULT) or -2 (NVMED_NOENTRY) is returned

### NVMED_QUEUE* nvmed_queue_create (NVMED* nvmed, int flags);
* Create an I/O queue 
* Argument
    * nvmed : pointer to the struct NVMED
    * flags : 
        * QUEUE_INTERRUPT - Enable Interrupt based I/O completion
* Return Value
    * On success, nvmed_queue_create() returns a pointer to the struct NVMED_QUEUE
    * ON error, NULL is returned
    
### int nvmed_queue_destroy (NVMED_QUEUE* queue);
* Destroy the I/O queue
* Argument
    * queue : pointer to the struct NVMED_QUEUE
* Return Value
    * On success, nvmed_queue_destroy() returns 0
    * On error, -1 (NVMED_FAULT) or -2 (NVMED_NOENTRY) is returned

### NVMED_HANDLE* nvmed_handle_create (NVMED_QUEUE* queue, int flags);
* Create an I/O handle for the I/O queue
* Argument
    * queue : pointer to the struct NVMED_QUEUE
    * flags :
        * HANDLE_DIRECT_IO - Perform I/O directly
        * HANDLE_SYNC_IO   - Perform I/O synchronously
        * HANDLE_INTERRUPT - Checking I/O completion using interrupt (must be used with interrupt enabled queue)
        * HANDLE_HINT_DMEM - Use the pre-translated buffer obtained from nvmed_get_buffer()
* Return Value
    * On success, nvmed_handle_create() returns a pointer to the struct NVMED_HANDLE
    * On error, NULL is returned
    
### int nvmed_handle_destroy (NVMED_HANDLE* handle);
* Destroy the I/O handle
* Argument
    * queue : pointer to the struct NVMED_HANDLE
* Return Value
    * On success, nvmed_queue_destroy() returns 0
    * On error, a negative value (-2, NVMED_NOENTRY) is returned

### NVMED_HANDLE* nvmed_handle_create_mq (NVMED_QUEUE** queues, int num_queue, int flags, NVMED_QUEUE* (*func)(NVMED_HANDLE* handle, u8 opcode, unsigned long offs, unsigned int len));
* Create an I/O handle for multiple queues
* Argument
    * queues : array of pointers to the struct NVMED_QUEUE
    * num_queue : number of queues in the array
    * flags : same as the flags used in nvmed_handle_create()
    * func: pointer to the callback function for selecting I/O queues among multiple queueus
* Return Value
    * On success, nvmed_handle_create_mq() returns a pointer to the struct NVMED_HANDLE
    * On error, NULL is returned

### int nvmed_handle_destroy_mq (NVMED_HANDLE* handle);
* Destroy the I/O handle for multiple queues
* Argument
    * queue : pointer to the struct NVMED_HANDLE, created by nvmed_handle_create_mq()
* Return Value
    * On success, nvmed_queue_destroy() returns 0
    * On error, a negative value (-2, NVMED_NOENTRY) is returned
    
### int nvmed_handle_feature_set (NVMED_HANDLE* handle, int flags, bool value);
* Set a feature for the handle
* Argument
    * handle : pointer to the strcut NVMED_HANDLE
    * flags
        * HANDLE_DIRECT_IO - perform direct I/O
        * HANDLE_SYNC_IO   - perform synchronous I/O
        * HANDLE_INTERRUPT - Checking I/O completion using interrupt (must be used with interrupt enabled queue)
        * HANDLE_HINT_DMEM - Use the pre-translated buffer obtained from nvmed_get_buffer()
    * value : TRUE or FALSE
* Return Value
    * value of flags (TRUE or FALSE)

### int nvmed_handle_feature_get (NVMED_HANDLE* handle, int flags);
* Inquire the current feature set for the handle
* Argument
    * handle : pointer to strcut NVMED_HANDLE
    * flags
        * HANDLE_DIRECT_IO - perform direct I/O
        * HANDLE_SYNC_IO   - perform synchronous I/O
        * HANDLE_HINT_DMEM - Use the pre-translated buffer obtained from nvmed_get_buffer()
* Return Value
    * value of flags (TRUE or FALSE)
    
### void* nvmed_get_buffer (NVMED* nvmed, unsigned int num_pages);
* Get an I/O buffer which is 4KB * num_pages in size
* Argument
    * num_pages : Number of pages to allocate
* Return Value
    * On success, nvmed_get_buffer() returns a pointer to the buffer
    * On error, NULL is returned

### void nvmed_put_buffer (void* ptr);
* Return the buffer to the framework so that the buffer can be released
* Argument
    * ptr : Pointer to the buffer


## Basic I/O

### off_t nvmed_lseek (NVMED_HANDLE* handle, off_t offset, int whence);
* Reposition read/write offset of the given handle
* For direct I/O, _offset_ should be aligned to the sector size (512 Bytes)
* Argument
    * handle : pointer to the struct NVMED_HANDLE
    * offset : byte offset according to the directive whence
    * whence
        * SEEK_SET : The offset is set to offset bytes
        * SEEK_CUR : The offset is set to its current location plus offset bytes
        * SEEK_END : The offset is set to the size of the device minus offset bytes
* Return Value
    * On success, nvmed_lseek() returns the offset location as measured in bytes 
      from the beginning of the device
    * On error, -1 is returned
        
### ssize_t nvmed_read (NVMED_HANDLE* handle, void* buf, size_t count);

### ssize_t nvmed_write (NVMED_HANDLE* handle, void* buf, size_t count);
* Read from or write to the device
* For direct I/O, _count_ should be aligned to the sector size (512 Bytes)
* Argument
    * handle : pointer to the struct NVMED_HANDLE
    * buf : pointer to the buffer
        * It is recommended to allocate the buffer by nvmed_get_buffer()
        * Otherwise, the memory region should be pinned explicitly using mlock() 
          and there will be slight overhead to translate the virtual address to 
          the physical address on every I/O
    * count : size of read/write bytes
* Return Value
    * On success, nvmed_read() or nvmed_write() returns the total bytes read or written
    * On error, -1 is returned
    
### int nvmed_flush (NVMED_HANDLE* handle);
* Flush dirty block cache to disk (for buffered writes using block cache) and 
  issue flush command 
* Argument
    * handle : pointer to the struct NVMED_HANDLE
* Return Value
    * On success, nvmed_flush() returns 0
    * On error, -1 is returned
    
### int nvmed_discard (NVMED_HANDLE* handle, unsigned long start, unsigned int len);
* Issue discard command to disk on specific region
* Argument
    * start : start bytes to discard
    * len : length (in bytes) to discard from the start bytes
    * _start/len_ should be aligned to the sector (512 Bytes)
* Return Value
    * On success, nvmed_discard() returns 0
    * On error, -1 is returned

## Asynchronous I/O

### int nvmed_aio_read (NVMED_AIO_CTX* context);

### int nvmed_aio_write (NVMED_AIO_CTX* context);
* Perform asynchronous read or write requests described by the pointer to the 
  struct NVMED_AIO_CTX
* _handle_, _start_lba_, _len_, and _buf_ of the structure pointed to by context 
  should be filled in advance to perform I/Os
* _start_lba_ should be aligned to the sector size (512 Bytes)
* _len_ should be aligned to the sector size (512 Bytes)
* Argument (member of the struct NVMED_AIO_CTX)
    * handle : pointer to the struct NVMED_HANDLE
    * start_lba : start bytes to read/write 
    * len : size of read/write bytes 
    * buf : pointer to the buffer
    * Optional
        * void (*aio_callback)(const struct nvmed_aio_ctx *context, void *userdata);
            * Callback function to be invoked when I/O is completed
        * cb_userdata : arguments for the callback function
        * private : private data for each context
* Return Value
    * On success, nvmed_aio_read() or nvmed_aio_write() returns 0
    * On error, -1 is returned
        
### int nvmed_aio_queue_submit (NVMED_HANDLE* handle);
* Return the number of submitted AIO contexts
* Argument
    * handle : pointer to the struct NVMED_HANDLE
* Return Value
    * nvmed_aio_queue_submit() returns the number of submitted AIO 
      contexts from the beginning or since the last call of nvmed_aio_queue_submit()

### int nvmed_aio_handle_complete (NVMED_HANDLE* handle);
* Complete the AIO context
* Argument
    * handle : pointer to the struct NVMED_HANDLE
* Return Value
    * nvmed_aio_handle_complete() returns the number of completed AIO contexts

### Status and completion of NVMED_AIO ###
* AIO Status (context->status)
    * AIO_INIT : AIO is queued
    * AIO_PROCESS : AIO is in progress
    * AIO_COMPLETE : AIO is completed
    
* Completion of AIO
    * AIO can be completed by calling the nvmed_aio_handle_complete() function.
    * Completed AIO context call the callback function (if specified) and
      the status flag of the context is set to AIO_COMPLETE


