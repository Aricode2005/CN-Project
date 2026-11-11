package arp.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Thread-safe fixed-capacity circular buffer.
 * Automatically evicts the oldest items when capacity is reached.
 *
 * @param <T> Item type
 */
public final class Ring<T> {
    private final Object[] array;
    private int head;
    private int size;

    public Ring(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("Capacity must be positive");
        }
        this.array = new Object[capacity];
    }

    public synchronized void add(T item) {
        array[(head + size) % array.length] = item;
        if (size < array.length) {
            size++;
        } else {
            head = (head + 1) % array.length;
        }
    }

    @SuppressWarnings("unchecked")
    public synchronized List<T> snapshot() {
        List<T> list = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            list.add((T) array[(head + i) % array.length]);
        }
        return list;
    }

    public synchronized int size() {
        return size;
    }

    public synchronized void clear() {
        head = 0;
        size = 0;
    }
}
