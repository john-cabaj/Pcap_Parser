import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.File;

public class TrafficPatterns 
{

	public static void main(String[] args) 
	{
		PcapParser parser = new PcapParser();
		
		parser.openFile("voip.pcap");
		Packet p = parser.getPacket();
		boolean good_cast = true;
		Packet last_p = null;
		boolean first_time = true;
		long last_time = 0;
		
		try
		{
			PrintWriter size = new PrintWriter("voip_size.txt");
			PrintWriter time = new PrintWriter("voip_time.txt");
			
			while(last_p != p)
			{
				if(p instanceof UDPPacket)
				{
					UDPPacket udp = (UDPPacket)p;
					size.println(udp.data.length);
					if(!first_time)
						time.println(udp.timestamp - last_time);
					last_time = udp.timestamp;
					first_time = false;
				}
				else if(p instanceof TCPPacket)
				{
					TCPPacket tcp = (TCPPacket)p;
					size.println(tcp.data.length);
					if(!first_time)
						time.println(tcp.timestamp - last_time);
					last_time = tcp.timestamp;
					first_time = false;
				}
				
				last_p = p;
				p = parser.getPacket();
			}
			
			parser.closeFile();
			size.close();
			time.close();
			
		}
		catch(FileNotFoundException fnfe)
		{
			System.out.println("File not found!");
		}
		
		
		
	}

}
