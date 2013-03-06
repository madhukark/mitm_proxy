package mitm;

public interface JSSEConstants
{
    public final static String KEYSTORE_PROPERTY = "javax.net.ssl.keyStore";
    public final static String KEYSTORE_PASSWORD_PROPERTY =
	"javax.net.ssl.keyStorePassword";
    public final static String KEYSTORE_TYPE_PROPERTY =
	"javax.net.ssl.keyStoreType";

    public final static String KEYSTORE_ALIAS_PROPERTY =
	"javax.net.ssl.keyStoreAlias";

    public final static String DEFAULT_ALIAS = "mykey";

    // File to collect stats information
    public final static String STATS_COUNT_FILE = ".statsFile";

    // File that has the hashed admin password for proxy client interaction
    public final static String PWD_FILE = "pwdFile";

    // KeyStore file that is used
    public final static String KEYSTORE_FILE = "keystore";
}
