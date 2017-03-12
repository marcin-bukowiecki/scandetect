package neuralnetwork;

import org.datavec.api.records.reader.RecordReader;
import org.datavec.api.records.reader.impl.csv.CSVRecordReader;
import org.datavec.api.split.FileSplit;
import org.datavec.api.util.ClassPathResource;
import org.deeplearning4j.datasets.datavec.RecordReaderDataSetIterator;
import org.deeplearning4j.nn.api.OptimizationAlgorithm;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.Updater;
import org.deeplearning4j.nn.conf.layers.DenseLayer;
import org.deeplearning4j.nn.conf.layers.OutputLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.deeplearning4j.optimize.listeners.ScoreIterationListener;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.dataset.DataSet;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

public class ScanDetectNeuralNetwork {

    private MultiLayerNetwork neuralNetwork;

    private static Logger log = LoggerFactory.getLogger(ScanDetectNeuralNetwork.class);

    /*
    Only for testing
     */
    public static void main(String[] args) throws IOException, InterruptedException {
        ScanDetectNeuralNetwork test = new ScanDetectNeuralNetwork();
        test.init();
    }

    /**
     * Inicjalizacja sieci neuronowej
     *
     * @throws IOException
     * @throws InterruptedException
     */
    public void init() throws IOException, InterruptedException {
        log.info("Initializing transport layer neural network.");

        //Czytanie pliku z danymi do nauki
        int numLinesToSkip = 0;
        String delimiter = ",";
        RecordReader recordReader = new CSVRecordReader(numLinesToSkip,delimiter);
        recordReader.initialize(new FileSplit(new ClassPathResource("learning_data.txt").getFile()));

        int labelIndex = 7;
        int batchSize = 150;

        DataSetIterator iterator = new RecordReaderDataSetIterator(recordReader,batchSize,labelIndex, labelIndex, true);
        DataSet allData = iterator.next();
        allData.shuffle();

        int numInput = 7;
        int numOutputs = 1;
        int nHidden = 10;
        int seed = 123;
        int iterations = 2000;
        double learningRate = 0.01;
        int nEpochs = 1;

        neuralNetwork = new MultiLayerNetwork(new NeuralNetConfiguration.Builder()
                .seed(seed)
                .iterations(iterations)
                .optimizationAlgo(OptimizationAlgorithm.STOCHASTIC_GRADIENT_DESCENT)
                .learningRate(learningRate)
                .weightInit(WeightInit.XAVIER)
                .updater(Updater.NESTEROVS).momentum(0.9)
                .list()
                .layer(0, new DenseLayer.Builder().nIn(numInput).nOut(nHidden)
                        .activation("tanh")
                        .build())
                .layer(1, new OutputLayer.Builder(LossFunctions.LossFunction.MSE)
                        .activation("identity")
                        .nIn(nHidden).nOut(numOutputs).build())
                .pretrain(false).backprop(true).build()
        );
        neuralNetwork.init();
        neuralNetwork.setListeners(new ScoreIterationListener(1));


        //Trenowanie
        for( int i=0; i<nEpochs; i++ ){
            iterator.reset();
            neuralNetwork.fit(iterator);
        }

        //Testy
        INDArray input = Nd4j.create(new double[] {1,1,1,1,0,0,0});
        INDArray out = neuralNetwork.output(input, false);
        System.out.println(out);
        input = Nd4j.create(new double[] {3,1,1,2,1,0,0.10});
        out = neuralNetwork.output(input, false);
        System.out.println(out);
        input = Nd4j.create(new double[] {3,2,1,3,1,1,1});
        out = neuralNetwork.output(input, false);
        System.out.println(out);
        input = Nd4j.create(new double[] {3,2,1,3,1,1,1});
        out = neuralNetwork.output(input, false);
        System.out.println(out);
        input = Nd4j.create(new double[] {3,1,1,2,1,0,0.60});
        out = neuralNetwork.output(input, false);
        System.out.println(out);
    }

    /**
     * Metoda oblicza z wykorzystaniem sieci neuronowej szansę wykonania ataku skanowania
     *
     * @param params lista wartości cech i współczynniki
     * @return wynik sieci neuronowej
     */
    private String getResult(List<Double> params) {
        System.out.println("Getting result from neural network...");
        System.out.println("=====================================");
        System.out.println("Initializing connection: " + params.get(0));
        System.out.println("Data transfer: " + params.get(1));
        System.out.println("Tried connect to closed port after open: " + params.get(2));
        System.out.println("Closed port threshold: " + params.get(3));
        System.out.println("Neighboring: " + params.get(4));
        System.out.println("Packet to open port factor: " + params.get(5));
        System.out.println("Attempts to connect to closed ports factor: " + params.get(6));

        final double[] args = new double[params.size()];
        int index = 0;
        for (Double arg : params) {
            args[index] = arg;
            index++;
        }
        final INDArray input = Nd4j.create(args);
        final INDArray out = neuralNetwork.output(input, false);

        System.out.println("Result is: " + out.toString());

        return out.toString();
    }

    /**
     * Metoda oblicza z wykorzystaniem sieci neuronowej szansę wykonania ataku skanowania
     *
     * @param params lista wartości cech i współczynniki
     * @return wynik sieci neuronowej w procentach
     */
    public int getResultAsPercentage(List<Double> params) {
        final String result = getResult(params);
        final double range = 2;
        final int rs = (int) (((Double.valueOf(result) - 1.00) / range) * 100.00);
        return rs > 100 ? 100 : rs < 0 ? 0 : rs;
    }
}
