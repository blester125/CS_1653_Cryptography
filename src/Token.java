import java.util.ArrayList;
import java.util.List;


public class Token implements UserToken {
	
	private static final long serialVersionUID = 897646161548165146L;

	private String issuer;
	private String subject;
	private ArrayList<String> groups;
	
	Token(String issuer, String subject, ArrayList<String> in_groups) {
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(in_groups.size());
		for(String group : in_groups)
			groups.add(group);
	}
	
	@Override
	public String getIssuer() {
		// TODO Auto-generated method stub
		return this.issuer;
	}

	@Override
	public String getSubject() {
		// TODO Auto-generated method stub
		return this.subject;
	}

	@Override
	public List<String> getGroups() {
		// TODO Auto-generated method stub
		return this.groups;
	}

	@Override
	public String toString() {
		return "Token [issuer=" + issuer + ", subject=" + subject + ", groups=" + groups + "]";
	}
	
}
