package utils

object NetworkLayerGroupKey {

  def apply(flowKey: Long, additionalHash: Long, additionalNetworkLayerHash: Long): NetworkLayerGroupKey = {
    new NetworkLayerGroupKey(flowKey, additionalHash, additionalNetworkLayerHash)
  }

}

class NetworkLayerGroupKey(val flowKey: Long, val additionalHash: Long, val additionalNetworkLayerHash: Long) {

  private val keyTuple = (flowKey, additionalHash, additionalNetworkLayerHash)

  override def hashCode(): Int = keyTuple.hashCode()

  override def equals(obj: scala.Any): Boolean = {
    if (obj == null || !obj.isInstanceOf[NetworkLayerGroupKey]) {
      false
    } else {
      obj.asInstanceOf[NetworkLayerGroupKey].keyTuple.equals(keyTuple)
    }
  }

}