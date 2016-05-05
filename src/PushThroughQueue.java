import java.util.LinkedList;

public class PushThroughQueue<T> {
	private int cap;
	private int size;
	private LinkedList<T> queue;

	public PushThroughQueue(int c) {
		this.cap = c;
		size = 0;
		queue = new LinkedList<T>();
	}

	public void add(T obj) {
		if (size >= cap) {
			queue.remove();
			size--;
		}
		queue.add(obj);
		size++;
	}

	public boolean contains(T obj) {
		return queue.contains(obj);
	}

	public int getSize() {
		return size;
	}

	public int getCap() {
		return cap;
	}

	public void print() {
		for (int i = 0; i < cap; i++) {
			System.out.print(queue.get(i));
			if (i != cap - 1) {
				System.out.print("->");
			}
		}
		System.out.println("");
	}

	public static void main(String args[]) {
		PushThroughQueue<String> q = new PushThroughQueue<String>(5);
		byte[] m = {'A', 'B'};
		byte[] n = {'C', 'D'};
		byte[] m1 = {'A', 'B'};
		q.add(Hasher.convertToString(m));
		q.add(Hasher.convertToString(n));
		System.out.println(q.contains(Hasher.convertToString(m1)));
	}	
}