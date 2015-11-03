/* Wormhole Attack Simulation with AODV Routing Protocol - Sample Program
 * 
 * Authors : Amita Kamath, Chirag Jamadagni
 *
 * Network topology
 * 
 *             n1 <------------> n2 
 *            /                    \
 *           /                      \
 *          n0                       n6
 *           \                      / 
 *            \                    /
 *             n4 -------------- n5
 *            
 * Each node is in the range of its immediate adjacent.
 * Source Node: n0
 * Destination Node: n6
 * Worm Tunnel: Between nodes n1 and n2
 * 
 * Output of this file:
 * 1. Generates blackhole.routes file for routing table information and
 * 2. blackhole.xml file for viewing animation in NetAnim.
 * 
 */

#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/mobility-module.h"
#include "myapp.h"

NS_LOG_COMPONENT_DEFINE ("Wormhole");

using namespace ns3;



void
ReceivePacket(Ptr<const Packet> p, const Address & addr)
{
	std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() <<"\n";
}


int main (int argc, char *argv[])
{
  bool enableFlowMonitor = false;
  std::string phyMode ("DsssRate1Mbps");

  CommandLine cmd;
  cmd.AddValue ("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.Parse (argc, argv);

//
// Explicitly create the nodes required by the topology (shown above).
//
  NS_LOG_INFO ("Create nodes.");
  NodeContainer c; // ALL Nodes
  NodeContainer not_malicious;
  NodeContainer malicious;
  c.Create(6);

  not_malicious.Add(c.Get(0));
  not_malicious.Add(c.Get(3));
  not_malicious.Add(c.Get(4));
  not_malicious.Add(c.Get(5));
  malicious.Add(c.Get(1));
  malicious.Add(c.Get(2));
  // Set up WiFi
  WifiHelper wifi;

  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11);

  YansWifiChannelHelper wifiChannel ;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::TwoRayGroundPropagationLossModel",
	  	  	  	  	  	  	  	    "SystemLoss", DoubleValue(1),
		  	  	  	  	  	  	    "HeightAboveZ", DoubleValue(1.5));

  // For range near 250m
  wifiPhy.Set ("TxPowerStart", DoubleValue(33));
  wifiPhy.Set ("TxPowerEnd", DoubleValue(33));
  wifiPhy.Set ("TxPowerLevels", UintegerValue(1));
  wifiPhy.Set ("TxGain", DoubleValue(0));
  wifiPhy.Set ("RxGain", DoubleValue(0));
  wifiPhy.Set ("EnergyDetectionThreshold", DoubleValue(-61.8));
  wifiPhy.Set ("CcaMode1Threshold", DoubleValue(-64.8));

  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a non-QoS upper mac
  NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
  wifiMac.SetType ("ns3::AdhocWifiMac");

  // Set 802.11b standard
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue(phyMode),
                                "ControlMode",StringValue(phyMode));


  NetDeviceContainer devices, mal_devices;
  devices = wifi.Install (wifiPhy, wifiMac, c);
  mal_devices = wifi.Install(wifiPhy, wifiMac, malicious);

//  Enable AODV
  AodvHelper aodv;
  AodvHelper malicious_aodv; 
 

  // Set up internet stack
  InternetStackHelper internet;
  internet.SetRoutingHelper (aodv);
  internet.Install (not_malicious);
  
  malicious_aodv.Set("EnableWrmAttack",BooleanValue(true)); // putting *false* instead of *true* would disable the malicious behavior of the node

  malicious_aodv.Set("FirstEndWifiWormTunnel",Ipv4AddressValue("10.0.1.1"));
  malicious_aodv.Set("FirstEndWifiWormTunnel",Ipv4AddressValue("10.0.1.2"));

  internet.SetRoutingHelper (malicious_aodv);
  internet.Install (malicious);

  // Set up Addresses
  Ipv4AddressHelper ipv4;
  NS_LOG_INFO ("Assign IP Addresses.");
  ipv4.SetBase ("10.0.1.0", "255.255.255.0");
  Ipv4InterfaceContainer ifcont = ipv4.Assign (devices);

  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer mal_ifcont = ipv4.Assign (mal_devices);



  NS_LOG_INFO ("Create Applications.");

  // UDP connection from N0 to N3

  uint16_t sinkPort = 6;
  Address sinkAddress (InetSocketAddress (ifcont.GetAddress (3), sinkPort)); // interface of n3
  PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
  ApplicationContainer sinkApps = packetSinkHelper.Install (c.Get (3)); //n3 as sink
  sinkApps.Start (Seconds (0.));
  sinkApps.Stop (Seconds (100.));

  Ptr<Socket> ns3UdpSocket = Socket::CreateSocket (c.Get (0), UdpSocketFactory::GetTypeId ()); //source at n0

  // Create UDP application at n0
  Ptr<MyApp> app = CreateObject<MyApp> ();
  app->Setup (ns3UdpSocket, sinkAddress, 1040, 5, DataRate ("250Kbps"));
  c.Get (0)->AddApplication (app);
  app->SetStartTime (Seconds (40.));
  app->SetStopTime (Seconds (100.));

// Set Mobility for all nodes

  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
  positionAlloc ->Add(Vector(100, 0, 0)); // node0
  positionAlloc ->Add(Vector(200, 0, 0)); // node1 
  positionAlloc ->Add(Vector(450, 0, 0)); // node2
  positionAlloc ->Add(Vector(550, 0, 0)); // node3
  positionAlloc ->Add(Vector(200, 10, 0)); // node4
  positionAlloc ->Add(Vector(450, 10, 0)); // node5

  mobility.SetPositionAllocator(positionAlloc);
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(c);


  AnimationInterface anim ("wormhole.xml"); // Mandatory
  AnimationInterface::SetConstantPosition (c.Get (0), 0, 500);
  AnimationInterface::SetConstantPosition (c.Get (1), 200, 500);
  AnimationInterface::SetConstantPosition (c.Get (2), 400, 500);
  AnimationInterface::SetConstantPosition (c.Get (3), 600, 500); 
  AnimationInterface::SetConstantPosition (c.Get (4), 200, 600);
  AnimationInterface::SetConstantPosition (c.Get (5), 400, 600); 

  anim.EnablePacketMetadata(true);

      Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("wormhole.routes", std::ios::out);
      aodv.PrintRoutingTableAllAt (Seconds (45), routingStream);

  // Trace Received Packets
  Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivePacket));


//
// Calculate Throughput using Flowmonitor
//
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();


//
// Now, do the actual simulation.
//
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds(100.0));
  Simulator::Run ();

  monitor->CheckForLostPackets ();

  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
	  Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
      if ((t.sourceAddress=="10.0.1.1" && t.destinationAddress == "10.0.1.4"))
      {
          std::cout << "  Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
          std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
          std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
      	  std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps\n";
      }
     }

  monitor->SerializeToXmlFile("lab-4.flowmon", true, true);


}
