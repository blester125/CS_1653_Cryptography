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

import java.util.ArrayList;
import java.util.Collections;

	/* This list represents the files on the server */
	public class FileList implements java.io.Serializable {
		
	/*Serializable so it can be stored in a file for persistence */
	private static final long serialVersionUID = -8911161283900260136L;
	private ArrayList<ShareFile> list;
	
	public FileList()
	{
		list = new ArrayList<ShareFile>();
	}
	
	public synchronized void addFile(String owner, String group, String path, int keyIndex, 
			int keyVersion, byte[] iv, long length)
	{
		ShareFile newFile = new ShareFile(owner, group, path, keyIndex, keyVersion, iv, length);
		list.add(newFile);
	}
	
	public synchronized void removeFile(String path)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getPath().compareTo(path)==0) {
				list.remove(i);
			}
		}
	}
	
	public synchronized boolean checkFile(String path)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getPath().compareTo(path)==0) {
				return true;
			}
		}
		return false;
	}
	
	public synchronized ArrayList<ShareFile> getFiles()
	{
		Collections.sort(list);
		return list;			
	}
	
	public synchronized ShareFile getFile(String path)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getPath().compareTo(path)==0) {
				return list.get(i);
			}
		}
		return null;
	}
}	
