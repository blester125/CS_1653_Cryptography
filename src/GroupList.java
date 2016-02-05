import java.util.*;

  public class GroupList implements java.io.Serializable {
    private static final long serialVersionUID = 8711454914678528003L;
    private Hashtable<String, Group> list = new Hashtable<String, Group>();
    
    public synchronized void addGroup(String groupName) {
      Group newGroup = new Group();
      list.put(groupName, newGroup);
    } 

    public synchronized void deleteGroup(String groupName) {
      list.remove(groupName);
    } 

    public synchronized boolean checkGroup(String groupName) {
      if (list.containsKey(groupName)) {
        return true;
      }
      return false;
    } 

    public synchronized ArrayList<String> getGroupUsers(String groupName) {
      return list.get(groupName).getUsers();
    }

    public synchronized String getGroupOwner(String groupName) {
      return list.get(groupName).getOwner();
    }

    public synchronized void addUser(String groupName, String userName) {
      list.get(groupName).addUser(userName);
    }

    public synchronized void deleteUser(String groupName, String userName) {
      list.get(groupName).removeUser(userName);
    }

  class Group implements java.io.Serializable {
    private static final long serialVersionUID = -7700097447400932609L;
    private ArrayList<String> users;
    private String owner;

    public Group() {
      users = new ArrayList<String>();
      ownership = new ArrayList<String>();
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