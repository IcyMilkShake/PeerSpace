class VolumeMeterProcessor extends AudioWorkletProcessor {
  process(inputs, outputs, parameters) {
    const input = inputs[0];
    if (input && input.length > 0 && input[0].length > 0) {
      const samples = input[0];
      let sum = 0;
      for (let i = 0; i < samples.length; ++i) {
        sum += samples[i] * samples[i];
      }
      const rms = Math.sqrt(sum / samples.length);
      this.port.postMessage({ volume: rms });
    }
    return true;
  }
}

registerProcessor('volume-meter-processor', VolumeMeterProcessor);
