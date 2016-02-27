import java.util.ArrayList;
import java.util.Date;
import java.util.List;


public class Token implements UserToken {
	
	private static final long serialVersionUID = 897646161548165146L;

	private String issuer;
	private String subject;
	private ArrayList<String> groups;
	private Date timestamp;
	
	private String sentinal = "#";
	
	Token(String issuer, String subject, ArrayList<String> in_groups) {
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(in_groups.size());
		for(String group : in_groups)
			this.groups.add(group);
		this.timestamp = new Date();
	}
	
	Token(String issuer, String subject, ArrayList<String> in_groups, Date timestamp) {
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(in_groups.size());
		for(String group : in_groups)
			this.groups.add(group);
		this.timestamp = timestamp;
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
		String token = this.timestamp + sentinal + this.issuer + sentinal + this.subject;
		for(String group : this.groups) {
			token += sentinal + group;
		}
		return token;
	}
	
}
