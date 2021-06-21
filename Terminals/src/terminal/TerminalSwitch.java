package terminal;

public interface TerminalSwitch {
    public void switchTerminal(byte t);
    public byte[] revokeCard(byte[] cardID);
    public boolean isRevokedCard(byte[] cardID);

    /**
     * Gets a terminal signature for the latest keyset.
     * @return 58 bytes: first two bytes are keyset ID; then 56 bytes of signature to rekey the card.
     * Signature signs:
     */
    public byte[] getRekeySignature();

    /**
     * Request the server to generate a new keyset, and distribute it.
     * @param rekeyCard should generate new card keypairs
     * @param rekeyTMan should generate new TMan keypairs
     * @param rekeyTChar etc.
     * @param rekeyTCons
     * @return the version number of the keyset
     */
    public short requestRekey(boolean rekeyCard, boolean rekeyTMan, boolean rekeyTChar, boolean rekeyTCons);
}