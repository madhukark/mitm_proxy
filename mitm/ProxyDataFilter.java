package mitm;

import java.io.PrintWriter;

import java.io.FileWriter;
import java.io.File;
import java.util.Scanner;

/*
 * This class is used to record data that passes back and forth over a TCP
 * connection.  Output goes to a PrintWriter, whose default value is System.out.

 * This just logs data to stdout or a file, but you can easily imagine how this could
 * be used to search for "interesting" data or even modify the data being transferred!
 *
 */

public class ProxyDataFilter {
    private PrintWriter m_out = new PrintWriter(System.out, true);

    public void setOutputPrintWriter(PrintWriter outputPrintWriter)  {
	m_out.flush();
	m_out = outputPrintWriter;
    }

    public PrintWriter getOutputPrintWriter() {
	return m_out;
    }

    public byte[] handle(ConnectionDetails connectionDetails,
			 byte[] buffer, int bytesRead)
	throws java.io.IOException
    {
	final StringBuffer stringBuffer = new StringBuffer();

	boolean inHex = false;

	for(int i=0; i<bytesRead; i++) {
	    final int value = (buffer[i] & 0xFF);
					
	    // If it's ASCII, print it as a char.
	    if (value == '\r' || value == '\n' ||
		(value >= ' ' && value <= '~')) {

		if (inHex) {
		    stringBuffer.append(']');
		    inHex = false;
		}

		stringBuffer.append((char)value);
	    }
	    else { // else print the value
		if (!inHex) {
		    stringBuffer.append('[');
		    inHex = true;
		}

		if (value <= 0xf) { // Where's "HexNumberFormatter?"
		    stringBuffer.append("0");
		}

		stringBuffer.append(Integer.toHexString(value).toUpperCase());
	    }
	}

	m_out.println("------ "+ connectionDetails.getDescription() +
		      " ------");
	m_out.println(stringBuffer);

        try {
            int requests = 0;

            File statsFile = new File(JSSEConstants.STATS_COUNT_FILE);
            if (! statsFile.exists()) {
                statsFile.createNewFile();
            }

            Scanner s = new Scanner(statsFile);
            while (s.hasNextInt()) {
                requests += s.nextInt();
            }
            requests ++;

            FileWriter outputStream = null;
            try {
                outputStream = new FileWriter(JSSEConstants.STATS_COUNT_FILE);
                outputStream.write(String.valueOf(requests));
            } finally {
                if (outputStream != null) {
                    outputStream.close();
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

	return null;
    }

    public void connectionOpened(ConnectionDetails connectionDetails) {
	m_out.println("--- " +  connectionDetails.getDescription() +
		      " opened --");
    }

    public void connectionClosed(ConnectionDetails connectionDetails) {
	m_out.println("--- " +  connectionDetails.getDescription() +
		      " closed --");
    }
}



