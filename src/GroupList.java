import java.util.*;

  public class GroupList implements java.io.Serializable {
    private static final long serialVersionUID = 8711454914678528003L;
    private Hashtable<String, Group> groups = new Hashtable<String, Group>();
    
    public synchronized void createGroup(String groupName, String username) {
      Group newGroup = new Group(username);
      groups.put(groupName, newGroup);
    } 

    public synchronized void deleteGroup(String groupName) {
    	groups.remove(groupName);
    } 

    public synchronized boolean checkGroup(String groupName) {
      if (groups.containsKey(groupName)) {
        return true;
      }
      return false;
    } 

    public synchronized ArrayList<String> getGroupUsers(String groupName) {
      return groups.get(groupName).getUsers();
    }

    public synchronized String getGroupOwner(String groupName) {
      return groups.get(groupName).getOwner();
    }

    public synchronized void addMember(String groupName, String userName) {
      groups.get(groupName).addUser(userName);
    }

    public synchronized void removeMember(String groupName, String userName) {
      groups.get(groupName).removeUser(userName);
    }

  class Group implements java.io.Serializable {
    private static final long serialVersionUID = -7700097447400932609L;
    private ArrayList<String> users;
    private String owner;

    public Group(String creator) {
      users = new ArrayList<String>();
      this.owner = creator;
    }

    public ArrayList<String> getUsers() {
      return users;
    }

    public String getOwner() {
      return owner;
    }

    public void addUser(String userName) {
      users.add(userName);
    }

    public void removeUser(String userName) {
      if (!users.isEmpty()) {
        if (users.contains(userName)) {
          users.remove(users.indexOf(userName));
        }
      }
    }
  }
}