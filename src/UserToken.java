/************************************
 * CS 1653 Term Project at the      *
 * University of Pittsburgh         *
 * Taught by Bill Garrison          *
 * Spring 2016                      *
 * By:                              *
 *   Brian Lester                   *
 *   Ryan Conley                    *
 *   Carmen Condeluci               *
 ************************************/

import java.util.List;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.SealedObject;
/**
 * A simple interface to the token data structure that will be
 * returned by a group server.  
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken extends java.io.Serializable
{
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer();


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();

    public List<String> getAliases();

    public boolean signToken(PrivateKey privateKey);

    public SealedObject getSignedHash();
    
    public Key getPublicKey();

    public String toString();
    
    /**
     * verifies that the token is fresh, as defined by being
     * within the bounds allowed for network latency (10s)
     * @return	true if within the allowed bounds given the current time,
     * else false
     */
    public boolean isFresh();

}   //-- end interface UserToken