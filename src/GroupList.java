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

    public synchronized ArrayList<String> getGroupOwnership(String groupName) {
      return list.get(groupName).getOwnership();
    }

    public synchronized void addUser(String groupName, String userName) {
      list.get(groupName).addUser(userName);
    }

    public synchronized void deleteUser(String groupName, String userName) {
      list.get(groupName).removeUser(userName);
    }

    public synchronized void addOwnership(String groupName, String userName) {
      list.get(groupName).addOwnership(userName);
    }

    public synchronized void removeOwnership(String groupName, String userName) {
      list.get(groupName).removeOwnership(userName);
    }

  class Group implements java.io.Serializable {
    private static final long serialVersionUID = -7700097447400932609L;
    private ArrayList<String> users;
    private ArrayList<String> ownership;

    public Group() {
      users = new ArrayList<String>();
      ownership = new ArrayList<String>();
    }

    public ArrayList<String> getUsers() {
      return users;
    }

    public ArrayList<String> getOwnership() {
      return ownership;
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

    public void addOwnership(String userName) {
      ownership.add(userName);
    }

    public void removeOwnership(String userName) {
      if (!ownership.isEmpty()) {
        if (ownership.contains(userName)) {
          ownership.remove(ownership.indexOf(userName));
        }
      }
    }

  }

  }