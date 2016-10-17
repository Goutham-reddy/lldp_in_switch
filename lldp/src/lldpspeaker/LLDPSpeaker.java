
package lldpspeaker;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.opendaylight.controller.liblldp.ConstructionException;
import org.opendaylight.controller.liblldp.EthernetAddress;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.yang.types.rev100924.MacAddress;
/*import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.inventory.rev130819.FlowCapableNodeConnector;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeConnectorRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeId;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.NodeRef;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.node.NodeConnector;
import org.opendaylight.yang.gen.v1.urn.opendaylight.inventory.rev130819.nodes.Node;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.PacketProcessingService;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.TransmitPacketInput;
import org.opendaylight.yang.gen.v1.urn.opendaylight.packet.service.rev130709.TransmitPacketInputBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.openflow.applications.lldp.speaker.rev141023.OperStatus;
import org.opendaylight.yangtools.yang.binding.InstanceIdentifier;*/
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;  
import java.util.ArrayList;  
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;  
  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapIf; 

/**
 * Objects of this class send LLDP frames over all flow-capable ports that can
 * be discovered through inventory.
 */
//public class LLDPSpeaker implements AutoCloseable, NodeConnectorEventsObserver,
public class LLDPSpeaker implements AutoCloseable,
        Runnable {

    private static final Logger LOG = LoggerFactory
            .getLogger(LLDPSpeaker.class);
    private static final long LLDP_FLOOD_PERIOD = 5;

    //private final PacketProcessingService packetProcessingService;
    private final ScheduledExecutorService scheduledExecutorService;
    private final Map<String, byte []> nodeConnectorMap = new ConcurrentHashMap<>();
    private final ScheduledFuture<?> scheduledSpeakerTask;
    //private final MacAddress addressDestionation;
    private final String destinationAddress = "01:23:00:00:00:01";
   //private OperStatus operationalStatus = OperStatus.RUN;
    private String operationalStatus = "RUN"; 
    //private String switch_name

   /* public LLDPSpeaker(final PacketProcessingService packetProcessingService,
            final MacAddress addressDestionation) {
        this(packetProcessingService, Executors
                .newSingleThreadScheduledExecutor(), addressDestionation);
    }*/

    public LLDPSpeaker() 
    {
    	scheduledExecutorService = Executors
                .newSingleThreadScheduledExecutor();
        scheduledSpeakerTask = this.scheduledExecutorService
                .scheduleAtFixedRate(this, 0,
                        LLDP_FLOOD_PERIOD, TimeUnit.SECONDS);
        LOG.info(
                "LLDPSpeaker started, it will send LLDP frames each {} seconds",
                LLDP_FLOOD_PERIOD);
    }
    /*
    public void setOperationalStatus(final OperStatus operationalStatus) {
        LOG.info("Setting operational status to {}", operationalStatus);
        this.operationalStatus = operationalStatus;
        if (operationalStatus.equals(OperStatus.STANDBY)) {
            nodeConnectorMap.clear();
        }
    }*/
/*
    public OperStatus getOperationalStatus() {
        return operationalStatus;
    }
*/
  

    /**
     * Closes this resource, relinquishing any underlying resources.
     */
    @Override
    public void close() {
        nodeConnectorMap.clear();
        scheduledExecutorService.shutdown();
        scheduledSpeakerTask.cancel(true);
        LOG.trace("LLDPSpeaker stopped sending LLDP frames.");
    }

    /**
     * Send LLDPDU frames to all known openflow switch ports.
     */
    @Override
    public void run() {
        if (operationalStatus.equals("RUN")) {
            LOG.info("Sending LLDP frames to {} ports...", nodeConnectorMap
                    .keySet().size());

            for (String eth_names: nodeConnectorMap
                    .keySet()) {
                LOG.trace("Sending LLDP through port {}",
                		eth_names);
                send_packet(eth_names, nodeConnectorMap.get(eth_names));
            }
        }
    }

  
    /**
     * {@inheritDoc}
     * @throws ConstructionException 
     * @throws SocketException 
     */
    //@Override
    
    public void addnode(byte switch_id) throws SocketException, ConstructionException
    {
    	LOG.info("Switch ID is {} ", switch_id );
    	String nodeId = "openflow:"+switch_id;
    	List<String> interfaces = (List<String>) enumerate_my_interfaces(switch_id);
    	
    	for(String value:interfaces)
        {
    		String nodeConnectorId = nodeId + ":" + value.charAt(value.length() - 1) ;
    		long outputPortNo = Character.getNumericValue((value.charAt(value.length() - 1)));
    		EthernetAddress e1 = new EthernetAddress(NetworkInterface.getByName(value).getHardwareAddress());
    		String MacAddress = e1.getMacAddress();
    		MacAddress srcMacAddress = new MacAddress(MacAddress.substring(MacAddress.indexOf("=") + 1, MacAddress.length()));
    		MacAddress addressDestionation = new MacAddress(destinationAddress);
    		byte[] packet = LLDPUtil.buildLldpFrame(nodeId, nodeConnectorId,
                    srcMacAddress, outputPortNo, addressDestionation);
    		nodeConnectorMap.put(value, packet); 
    		System.out.println("nodeConnectorId" + nodeConnectorId + "  outputPortNo" + outputPortNo + "  srcMacAddress" + 
    				srcMacAddress.getValue() + "  addressDestionation" + addressDestionation.getValue());
    		 
        }
    }
  /* public void nodeConnectorAdded(
            final InstanceIdentifier<NodeConnector> nodeConnectorInstanceId,
            final FlowCapableNodeConnector flowConnector) {
        NodeConnectorId nodeConnectorId = InstanceIdentifier.keyOf(
                nodeConnectorInstanceId).getId();

        // nodeConnectorAdded can be called even if we already sending LLDP
        // frames to
        // port, so first we check if we actually need to perform any action
        if (nodeConnectorMap.containsKey(nodeConnectorInstanceId)) {
            LOG.trace(
                    "Port {} already in LLDPSpeaker.nodeConnectorMap, no need for additional processing",
                    nodeConnectorId.getValue());
            return;
        }

        // Prepare to build LLDP payload
        InstanceIdentifier<Node> nodeInstanceId = nodeConnectorInstanceId
                .firstIdentifierOf(Node.class);
        NodeId nodeId = InstanceIdentifier.keyOf(nodeInstanceId).getId();
        MacAddress srcMacAddress = flowConnector.getHardwareAddress();
        Long outputPortNo = flowConnector.getPortNumber().getUint32();

        // No need to send LLDP frames on local ports
        if (outputPortNo == null) {
            LOG.trace("Port {} is local, not sending LLDP frames through it",
                    nodeConnectorId.getValue());
            return;
        }

  
        LLDPUtil.buildLldpFrame(nodeId, nodeConnectorId,
                                srcMacAddress, outputPortNo,
                                addressDestionation)).build();

        // Save packet to node connector id -> packet map to transmit it every 5
        // seconds
        nodeConnectorMap.put(nodeConnectorInstanceId, packet);
        LOG.trace("Port {} added to LLDPSpeaker.nodeConnectorMap",
                nodeConnectorId.getValue());

        // Transmit packet for first time immediately
        packetProcessingService.transmitPacket(packet);
    }

    /**
     * {@inheritDoc}
     */
   // @Override 
 /*   public void nodeConnectorRemoved(
            final InstanceIdentifier<NodeConnector> nodeConnectorInstanceId) {
        nodeConnectorMap.remove(nodeConnectorInstanceId);
        NodeConnectorId nodeConnectorId = InstanceIdentifier.keyOf(
                nodeConnectorInstanceId).getId();
        LOG.trace("Port {} removed from LLDPSpeaker.nodeConnectorMap",
                nodeConnectorId.getValue());
    }
   */
    public static void main(String command_args[]) throws SocketException, ConstructionException
    {
    	byte switch_id = (byte) Integer.parseInt(command_args[0]);
    	
    	
    	LLDPSpeaker lldpspeaker = new LLDPSpeaker();
    	lldpspeaker.addnode(switch_id);
		
		//MacAddress m1= new MacAddress("00:00:00:00:00:01");
		//System.out.println(m1.getValue());
    	
    	
    }
    
    private List<?> enumerate_interfaces(){
    	
    	List<String> interfaces = new ArrayList<>();
    	 try {
			Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
			
			for (NetworkInterface netint : Collections.list(nets))
				interfaces.add(netint.getName().trim());
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	return interfaces;
    }
    
    private List<?> enumerate_my_interfaces(byte switch_id)
    {
    
    	
    	String start_name = "s"+switch_id+"-eth";
    	LOG.info("start_name is {} ", start_name);
    	List<String> interfaces = (List<String>) enumerate_interfaces();
    	List<String> my_interfaces = new ArrayList<>();
    	for(String inte_name:interfaces)
    	{
    		if(inte_name.startsWith(start_name))
    			my_interfaces.add(inte_name);
    		
    	}
    	
    	
    	return my_interfaces;
    }
    
    private static int send_packet(String interface_name, byte payload[])
    {
    	System.out.println("send_packet" + interface_name);
    	List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
        
        /*************************************************************************** 
         * First get a list of devices on this system 
         **************************************************************************/  
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
          System.err.printf("Can't read list of devices, error is %s", errbuf.toString());  
          return 0;  
        }  
        //PcapIf device = alldevs.get(6); // We know we have atleast 1 device  
        System.out.println(alldevs.size());
        char check = 0;
        for(PcapIf pp:alldevs) {
			String add = pp.getName().trim() ;
			System.out.println(add);
			if(add.equals(interface_name))
			{
				 check =1;
			     break;
			}
		}
        
        if(check == 0)
        	System.out.println("Error as interface" + interface_name + " do not appear in the system"); 
        
        /***************************************** 
         * Second we open a network interface 
         *****************************************/  
        int snaplen = 64 * 1024; // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000; // 10 seconds in millis  
        Pcap pcap = Pcap.openLive(interface_name, snaplen, flags, timeout, errbuf);  
        
      
        /******************************************************* 
         * Third we create our crude packet we will transmit out 
         * This creates a broadcast packet 
         *******************************************************/  
        byte[] a = new byte[payload.length];  
        Arrays.fill(a, (byte) 0x00);
        a = Arrays.copyOf(payload, payload.length);  
        ByteBuffer b = ByteBuffer.wrap(a);  
        
        /******************************************************* 
         * Fourth We send our packet off using open device 
         *******************************************************/  
        if (pcap.sendPacket(a) != Pcap.OK) {  
          System.err.println("Send packet error" + pcap.getErr());  
        }  
      
        /******************************************************** 
         * Lastly we close 
         ********************************************************/  
        pcap.close();  
        
		return 1;
    	
    }
}
