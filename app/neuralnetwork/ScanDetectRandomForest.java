package neuralnetwork;

import weka.classifiers.Evaluation;
import weka.classifiers.trees.RandomForest;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SparseInstance;
import weka.core.converters.CSVLoader;

import java.io.File;
import java.util.List;

public class ScanDetectRandomForest {

    private RandomForest randomForest;

    public static void main(String[] args) throws Exception {
        ScanDetectRandomForest scanDetectRandomForest = new ScanDetectRandomForest();
        scanDetectRandomForest.init();
    }

    public void init() throws Exception {
        CSVLoader csvLoader = new CSVLoader();
        csvLoader.setSource(new File("./conf/learning_data.csv"));
        Instances dataSet = csvLoader.getDataSet();
        dataSet.setClassIndex(7);

        RandomForest randomForest = new RandomForest();
        randomForest.setNumFeatures(7);
        randomForest.buildClassifier(dataSet);

        Evaluation evaluation = new Evaluation(dataSet);
        evaluation.evaluateModel(randomForest, dataSet);

        System.out.println(evaluation.toSummaryString());

        Instance instance = new SparseInstance(7);
        instance.setValue(0, 1);
        instance.setValue(1, 1);
        instance.setValue(2, 1);
        instance.setValue(3, 1);
        instance.setValue(4, 0.02);
        instance.setValue(5, 0.01);
        instance.setValue(6, 0.03);
        dataSet.add(instance);
        instance.setDataset(dataSet);
        System.out.println("Test classification for non attack: " + randomForest.classifyInstance(instance));

        instance = new SparseInstance(7);
        instance.setValue(0, 0);
        instance.setValue(1, 1);
        instance.setValue(2, 1);
        instance.setValue(3, 2);
        instance.setValue(4, 0.98);
        instance.setValue(5, 0.01);
        instance.setValue(6, 0.61);
        dataSet.add(instance);
        instance.setDataset(dataSet);
        System.out.println("Test classification for a potential attack: " + randomForest.classifyInstance(instance));

        instance = new SparseInstance(7);
        instance.setValue(0, 0);
        instance.setValue(1, 3);
        instance.setValue(2, 3);
        instance.setValue(3, 3);
        instance.setValue(4, 0.87);
        instance.setValue(5, 0.92);
        instance.setValue(6, 0.93);
        dataSet.add(instance);
        instance.setDataset(dataSet);
        System.out.println("Test classification for an attack: " + randomForest.classifyInstance(instance));
        this.randomForest = randomForest;
    }

    public int getResultAsPercentage(List<Double> params) {
        final String result = getResult(params);
        return (int) (Double.valueOf(result) * 100.00);
    }

    private String getResult(List<Double> params) {
        System.out.println("Getting result from random forest...");
        System.out.println("=====================================");
        System.out.println("Initializing connection: " + params.get(0));
        System.out.println("Data transfer: " + params.get(1));
        System.out.println("Tried connect to closed port after open: " + params.get(2));
        System.out.println("Closed port threshold: " + params.get(3));
        System.out.println("Neighboring: " + params.get(4));
        System.out.println("Packet to open port factor: " + params.get(5));
        System.out.println("Attempts to connect to closed ports factor: " + params.get(6));

        Instance instance = new SparseInstance(7);
        int index = 0;
        for (Double arg : params) {
            instance.setValue(index, arg);
            index++;
        }

        double out;
        try {
            out = randomForest.classifyInstance(instance);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        final String result = String.valueOf(out);
        System.out.println("Result is: " + result);

        return result;
    }
}
