import java.util.ArrayList;


public class Envelope implements java.io.Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7726335089122193103L;
	private String msg;
	private ArrayList<Object> objContents = new ArrayList<Object>();
	
	public Envelope(String text)
	{
		msg = text;
	}
	
	public String getMessage()
	{
		return msg;
	}
	
	public ArrayList<Object> getObjContents()
	{
		return objContents;
	}
	
	public void addObject(Object object)
	{
		objContents.add(object);
	}

	@Override
	public String toString() {
		return "Envelope [msg=" + msg + ", objContents=" + objContents + "]";
	}

	public static Envelope buildSuper(Envelope env, SecretKey key) {
		IvParameterSpec ivSpec = CipherBox.generateRandomIV();
		Envelope superEnv = new Envelope("SUPER");
		SealedObject sealedEnv = CipherBox.(env, key, ivSpec);
		String HMAC = Hasher.generateHMAC(key, sealedEnv);
		superE.add(superEnv);
		superE.add(ivSpec);
		superE.add(HMAC);
		return superE;
	}

	public static Envelope extractInner(Envelope env, SecretKey, key) {
		if (env != null) {
			if (env.getObjContents().length == 3) {
				if (env.getObjContents().get(0) != null) {
					if (env.getObjContents().get(1) != null) {
						if (env.getObjContents().get(2) != null) {
							SealedObject sealedEnv = (SealedObject)env.getObjContents().get(0);
							IvParameterSpec ivSpec = new IvParameterSepc((byte[])env.getObjContents().get(1));
							String HMAC = env.getObjContents().get(2);
							if (Hasher.verifyHMAC(HMAC, key, sealedEnv)) {
								return (Envelope)CipherBox.decrypt(sealedObj, key, ivSpec);
							}
						}
					}
				}
			}
		}
		return null;
	}
	}

}
