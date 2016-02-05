import java.util.ArrayList;
import java.util.List;


public class Token implements UserToken {
	
	private String issuer;
	private String subject;
	private List<String> groups;
	
	Token(String issuer, String subject, List<String> groups) {
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(groups);
	}
	
	@Override
	public String getIssuer() {
		// TODO Auto-generated method stub
		return issuer;
	}

	@Override
	public String getSubject() {
		// TODO Auto-generated method stub
		return subject;
	}

	@Override
	public List<String> getGroups() {
		// TODO Auto-generated method stub
		return groups;
	}
	
}
