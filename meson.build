project('csh_xbee', 'c', subproject_dir: 'lib', default_options: [
    'buildtype=debug', 
    'c_std=gnu11', 
    'b_lto=false',
    'b_lundef=false',
    'param:list_dynamic=true',
    'default_library=shared',
    'param:scheduler=false',
    'param:scheduler_client=false',
    'param:commands=false',
    'param:commands_client=false',
    'csp:packet_padding_bytes=42', 
    'csp:buffer_count=1000',
    'csp:buffer_size=2048',
    'csp:conn_max=20',
    'csp:conn_rxqueue_len=1000',
    'csp:qfifo_len=1000',
    'csp:rdp_max_window=1000',
    'csp:port_max_bind=16',
    'csp:use_rtable=true',
])

add_global_arguments('-I../include', language: 'c')

dependencies = []
dependencies += dependency('apm_csh', fallback: ['apm_csh', 'apm_csh_dep'], required: true)

addin_sources = [
    'src/xbee.c',
]

addin_lib = library('csh_xbee',
                    addin_sources,
                    dependencies : dependencies,
                    link_args : ['-Wl,-Map=cshmodtest.map', '-lm'],
                    install : true)
