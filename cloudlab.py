"""Network Configuration for zk-netfilter"""

#
# NOTE: This code was machine converted. An actual human would not
#       write code like this!
#

# Import the Portal object.
import geni.portal as portal
# Import the ProtoGENI library.
import geni.rspec.pg as pg
# Import the Emulab specific extensions.
import geni.rspec.emulab as emulab

# Create a portal object,
pc = portal.Context()
pc.defineParameter( "n", "Number of clients", portal.ParameterType.INTEGER, 1 )
pc.defineParameter( "client_hardware", "Client Hardware Type", portal.ParameterType.STRING, "m510")
pc.defineParameter( "middlebox_hardware", "Middlebox Hardware Type", portal.ParameterType.STRING, "m510")
pc.defineParameter( "tlsserver_hardware", "Middlebox Hardware Type", portal.ParameterType.STRING, "m510")
pc.defineParameter( "second_middlebox_hardware", "Second Middlebox Hardware Type", portal.ParameterType.STRING, "NONE")
params = pc.bindParameters()

# Create a Request object to start building the RSpec.
request = pc.makeRequestRSpec()

# Check parameter validity.
if params.n < 1:
    portal.context.reportError( portal.ParameterError( "You must choose at least 1 client.", ["n"] ) )

# Abort execution if there are any errors, and report them.
portal.context.verifyParameters()

# Link link-1
link_1 = request.Link('link-1')
link_1.Site('undefined')


dataset_urn = "urn:publicid:IDN+utah.cloudlab.us:zombie-pg0+imdataset+netfilter_data"

for i in range( params.n ):
    client_node = request.RawPC("client_node" + str(i))
    client_node.site = 'SiteA'
    client_node.hardware_type = params.client_hardware
    # client_node.disk_image = "urn:publicid:IDN+utah.cloudlab.us+image+zombie-PG0:netfilter.client_node1"
    client_bs = client_node.Blockstore("client_bs" + str(i), "/mydata")
    client_bs.dataset = dataset_urn
    client_iface = client_node.addInterface("client_interface" + str(i), pg.IPv4Address('192.168.0.' + str(i + 5),'255.255.255.0'))
    link_1.addInterface(client_iface)
    # command = "cd ~; pwd; git config --global credential.helper store;" + clone_command + "cd ~/zk-dns-filter/CodeSnippets/prototype/prover; ./configure.sh;"
    # client_node.addService(pg.Execute(shell="bash", command=command))
    

middlebox_node = request.RawPC('middlebox_node')
middlebox_node.site = 'SiteA'
middlebox_node.hardware_type = params.middlebox_hardware
# middlebox_node.disk_image = "urn:publicid:IDN+utah.cloudlab.us+image+zombie-PG0:netfilter.client_node1"
bs0 = middlebox_node.Blockstore("bs0", "/mydata")
bs0.dataset = dataset_urn
iface1 = middlebox_node.addInterface('interface-4', pg.IPv4Address('192.168.0.1','255.255.255.0'))
link_1.addInterface(iface1)
# command = "cd ~; pwd; git config --global credential.helper store;" + clone_command + "cd ~/zk-dns-filter/CodeSnippets/prototype/middlebox_rust; ./configure.sh; sudo ./iptables_configure.sh " + str(params.n) + ";"
# middlebox_node.addService(pg.Execute(shell="bash", command=command))

middlebox_node = request.RawPC('tlsserver_node')
middlebox_node.site = 'SiteA'
middlebox_node.hardware_type = params.tlsserver_hardware

if params.second_middlebox_hardware != 'NONE':
    second_middlebox_node = request.RawPC('second_middlebox_node')
    second_middlebox_node.hardware_type = params.second_middlebox_hardware
    second_middlebox_bs = second_middlebox_node.Blockstore("second_middlebox_bs", "/mydata")
    second_middlebox_bs.dataset = dataset_urn
    second_middlebox_iface = second_middlebox_node.addInterface('second_middlebox_interface', pg.IPv4Address('192.168.0.2','255.255.255.0'))
    link_1.addInterface(second_middlebox_iface)
    # command = "cd ~; pwd; git config --global credential.helper store;" + clone_command + "cd ~/zk-dns-filter/CodeSnippets/prototype/middlebox_rust; ./configure.sh; sudo ./iptables_configure.sh " + str(params.n) + ";"
    # second_middlebox_node.addService(pg.Execute(shell="bash", command=command))

# Print the generated rspec
pc.printRequestRSpec(request)
